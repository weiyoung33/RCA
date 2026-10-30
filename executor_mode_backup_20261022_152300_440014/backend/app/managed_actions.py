"""Admin-authored action definitions, rendered to the existing catalog v1 spec.

Only final activation writes the catalog. Drafting never executes source,
connects to the target, or lets model text become an executable command.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import shlex
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


SOP_MARKER = "<!-- RCA_ADMIN_ACTION_SOP_V1 -->"
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{2,127}$")


def _validate_source_policy(policy):
    if set(policy)-{'predicates','unresolved'} or not isinstance(policy.get('predicates'),list) or len(policy['predicates'])>40 or type(policy.get('unresolved',False)) is not bool:
        raise ValueError('Invalid extracted health policy; refresh the source suggestions')
    def condition(value,depth=0):
        if depth>12 or not isinstance(value,dict): raise ValueError('Invalid extracted condition')
        op=value.get('op')
        if op in {'And','Or'}:
            if not isinstance(value.get('values'),list) or not 1<=len(value['values'])<=40: raise ValueError('Invalid extracted condition list')
            for child in value['values']: condition(child,depth+1)
        elif op=='Not': condition(value.get('value'),depth+1)
        elif op in {'Eq','NotEq','Gt','GtE','Lt','LtE'}:
            for operand in (value.get('left'),value.get('right')):
                if not isinstance(operand,dict): raise ValueError('Invalid extracted measurement')
                if set(operand)=={'metric'} and operand['metric'] in {'process_count','memory_percent','cpu_percent'}: continue
                if set(operand)=={'literal'} and type(operand['literal']) in (str,int,float,bool):
                    if isinstance(operand['literal'],float) and not math.isfinite(operand['literal']): raise ValueError('Nonfinite source threshold')
                    continue
                raise ValueError('Unsupported extracted measurement')
        else: raise ValueError('Unsupported extracted condition')
    for value in policy['predicates']: condition(value)


class ManagedActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    action_id: str = Field(min_length=3, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=5000)
    operation: Literal["CUSTOM_COMMAND", "RESTART_SCRIPT", "TRIM_PROCESSES", "STOP_PROCESSES"]
    command: str = Field(default="", max_length=16000)
    process_path: str = Field(default="", max_length=1000)
    owner: str = Field(default="", max_length=255)
    python_executable: str = Field(default="python3", max_length=1000)
    expected_count: int = Field(default=1, ge=1, le=100)
    max_matches: int = Field(default=20, ge=1, le=1000)
    signal: Literal["TERM", "KILL"] = "TERM"
    stop_timeout_seconds: int = Field(default=15, ge=1, le=120)
    command_timeout_seconds: int = Field(default=60, ge=5, le=600)
    health_command: str = Field(default="", max_length=16000)
    healthy_stdout_regex: str = Field(default="", max_length=2000)
    unhealthy_stdout_regex: str = Field(default="", max_length=2000)
    source_health_policy: Optional[dict] = None
    verification_attempts: int = Field(default=6, ge=1, le=20)
    verification_delay_seconds: int = Field(default=5, ge=0, le=30)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    recovery_notes: str = Field(default="", max_length=5000)

    @model_validator(mode="after")
    def validate_definition(self):
        if not ID.fullmatch(self.action_id):
            raise ValueError("Action ID: use 3–128 lowercase letters, digits, underscores or hyphens")
        if self.operation != "CUSTOM_COMMAND":
            if not self.process_path.startswith("/") or "\0" in self.process_path:
                raise ValueError("Enter the exact absolute script path used in its process arguments")
            if self.operation!='STOP_PROCESSES' and self.max_matches < self.expected_count:
                raise ValueError("Maximum matches must be at least the expected count")
            if not re.fullmatch(r"[A-Za-z0-9_./-]+", self.python_executable):
                raise ValueError("Python executable must be one executable name or path")
        if self.operation in {"CUSTOM_COMMAND", "RESTART_SCRIPT"} and not self.command:
            raise ValueError("Enter the exact command to execute")
        if self.operation == "CUSTOM_COMMAND" and not self.health_command:
            raise ValueError("Enter a read-only health check for the custom command")
        if re.search(r"(?<!\$)\{(?:pid|pids)\}|<(?:pid|pids)>", self.command, re.IGNORECASE) and self.operation == "CUSTOM_COMMAND":
            raise ValueError("Use a fixed reviewed command or the process action type; do not leave runtime placeholders")
        if self.health_command and not self.healthy_stdout_regex:
            raise ValueError("Enter the expected healthy output pattern")
        if self.source_health_policy and self.source_health_policy.get('unresolved') and not self.health_command:
            raise ValueError('Some source conditions are unresolved. Enter a health check for those conditions or refresh the deployed source values.')
        if self.source_health_policy:
            _validate_source_policy(self.source_health_policy)
        for pattern in (self.healthy_stdout_regex, self.unhealthy_stdout_regex):
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError("Invalid health output pattern: " + str(exc)) from exc
        if "\0" in self.command or "\0" in self.health_command:
            raise ValueError("Commands cannot contain NUL characters")
        # Obvious mutating commands are actions, not health checks. Custom
        # diagnostics remain administrator-reviewed; no DAG-name allowlist.
        if re.search(r"(?:^|[;&|\n]\s*)(?:sudo\s+)?(?:kill|pkill|killall|reboot|shutdown|rm)\b"
                     r"|\bsystemctl\s+(?:restart|start|stop)\b", self.health_command):
            raise ValueError("The health check contains a state-changing command")
        return self


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fixed_python(executable, program, argument=""):
    result = shlex.quote(executable) + " -c " + shlex.quote(program)
    return result + (" " + shlex.quote(argument) if argument else "")


def process_probe(value):
    # Separate read-only program: no signal or subprocess APIs in diagnostics.
    program = '''import json, pathlib, pwd, sys
c = json.loads(sys.argv[1])
count = 0
for p in pathlib.Path('/proc').iterdir():
    if not p.name.isdigit() or int(p.name) <= 1:
        continue
    try:
        argv = [x.decode('utf-8', 'surrogateescape') for x in (p/'cmdline').read_bytes().split(b'\\0') if x]
        if c['process_path'] not in argv:
            continue
        if c.get('owner') and pwd.getpwuid(p.stat().st_uid).pw_name != c['owner']:
            continue
        stat = (p/'stat').read_text()
        if stat[stat.rfind(')')+2:].split()[0] != 'Z':
            count += 1
    except (FileNotFoundError, ProcessLookupError):
        continue
print(count)
'''
    # Nonzero exit 2 is diagnostic failure, never a valid unhealthy count.
    program = "try:\n" + "\n".join("    " + line for line in program.splitlines()) + "\nexcept Exception as exc:\n    print(str(exc), file=__import__('sys').stderr)\n    raise SystemExit(2)\n"
    return _fixed_python(value.python_executable, program,
                         _json({"process_path": value.process_path, "owner": value.owner}))


def compile_action(value, component_id, target_id):
    value = ManagedActionInput.model_validate(value) if isinstance(value, dict) else value
    if value.operation == "CUSTOM_COMMAND":
        command = value.command
    else:
        program = Path(__file__).with_name("managed_process.py").read_text(encoding="utf-8")
        config = {key: getattr(value, key) for key in ("operation", "process_path", "owner", "signal", "max_matches", "expected_count", "stop_timeout_seconds", "command")}
        config["start_timeout_seconds"] = value.command_timeout_seconds
        command = _fixed_python(value.python_executable, program, _json(config))
    policy_check=bool(value.source_health_policy and not value.health_command)
    if policy_check:
        from .action_candidates import _health_command
        health_command=_health_command(value.process_path,value.owner,value.python_executable,
                                       value.source_health_policy['predicates'],value.operation,value.expected_count)
    else:
        health_command = value.health_command or process_probe(value)
    if value.health_command and value.operation!='CUSTOM_COMMAND':
        # Keep an extracted predicate bound to the process scope the admin
        # actually selected, including edits made after automatic prefill.
        try:
            from .action_candidates import _health_command
            parts=shlex.split(value.health_command)
            if len(parts)==4 and parts[1]=='-c' and parts[2].startswith('# RCA_SOURCE_HEALTH_V1\n'):
                config=json.loads(parts[3])
                canonical=_health_command(config['path'],config['owner'],parts[0],config['predicates'],config['operation'],config['expected'])
                if canonical==value.health_command:
                    health_command=_health_command(value.process_path,value.owner,value.python_executable,config['predicates'],value.operation,value.expected_count)
        except (ValueError,KeyError,IndexError,TypeError):
            pass
    expected = 0 if value.operation == "STOP_PROCESSES" else value.expected_count
    healthy = 'HEALTHY' if policy_check else (value.healthy_stdout_regex if value.health_command else str(expected))
    counts = range(expected + 1, value.max_matches + 1) if value.operation in {"TRIM_PROCESSES","STOP_PROCESSES"} else (n for n in range(value.max_matches + 1) if n != expected)
    unhealthy = 'ACTION_REQUIRED' if policy_check else (value.unhealthy_stdout_regex if value.health_command else "(?:" + "|".join(map(str, counts)) + ")")
    check = {"kind": "command", "name": "application_health", "command": health_command,
             "expected_exit_codes": [0], "unhealthy_exit_codes": [1],
             "timeout_seconds": 15, "require_stdout": True,
             "healthy_stdout_regex": healthy,
             "unhealthy_stdout_regex": unhealthy or None}
    timeout = value.command_timeout_seconds
    if value.operation != "CUSTOM_COMMAND":
        timeout += value.stop_timeout_seconds + 10
    spec = {"schema_version": 1, "command": command, "command_timeout_seconds": timeout,
            "prechecks": [check], "postchecks": [dict(check)],
            "verification_attempts": value.verification_attempts,
            "verification_delay_seconds": value.verification_delay_seconds}
    if len(command) > 16000:
        raise ValueError("Generated command exceeds the catalog limit; use a reviewed fixed helper command")
    return {"action_id": value.action_id, "component_id": component_id, "target_id": target_id,
            "display_name": value.display_name, "description": value.description or value.display_name,
            "risk_level": value.risk_level, "lifecycle_status": "ACTIVE",
            "implementation_version": "admin-" + hashlib.sha256(_json(spec).encode()).hexdigest()[:32],
            "executor_type": "SSH_COMMAND", "execution_spec": spec,
            "verification_summary": "Live health check before execution and after completion.",
            "rollback_summary": value.recovery_notes or None, "requires_approval": True}


def _target_id(registration):
    mode = registration.get("mode")
    if mode == "EXISTING":
        return registration.get("target_id", "")
    if mode == "NEW":
        return registration.get("target", {}).get("target_id", "")
    raise ValueError("Execution mode requires an SSH target; database investigation remains read-only")


def extraction_draft(request, response_model):
    from .action_candidates import extract_action_candidates
    structured=request.structured_input
    result=extract_action_candidates(structured.dag_source_code, structured.airflow_variable_values, structured.dag_id)
    registration=structured.target_registration.model_dump(mode='json')
    if registration.get('mode')=='NEW' and 'credential_plan' in registration:
        registration['credential_plan']['executor']=None
    return response_model.model_validate({
        "assistant_message":"Detected actions are ready to review; no commands were executed.",
        "ready_for_review":False,"missing_fields":[],"validation_issues":[],
        "source_plan":{},"confirmation_questions":[],"explanation_notes":[],"action_extraction":result,
        "draft":{"schema_version":1,"lifecycle_status":"DRAFT","operating_mode":"INVESTIGATE_ONLY",
            "dag":{"dag_id":structured.dag_id,"exception_types":structured.exception_types,"investigation_sop":""},
            "target_registration":registration,
            "selected_action_id":None,"remediation_action":None,
            "review_template":{"summary":"Review extracted actions in the action form.","sop_review_points":[],"action_review_points":[],"activation_requirements":[]}}})


def _existing_action(cursor, action_id, dag_id, target_id):
    cursor.execute("""SELECT action_id, component_id, target_id, display_name, description,
        risk_level, lifecycle_status, implementation_version, executor_type,
        execution_spec, verification_summary, rollback_summary, requires_approval
        FROM remediation_action_catalog WHERE action_id = %s""", (action_id,))
    row = cursor.fetchone()
    if not row or row["lifecycle_status"] != "ACTIVE" or not row["requires_approval"]:
        raise ValueError("Select an ACTIVE action requiring approval")
    if row["component_id"] != dag_id or row["target_id"] != target_id:
        raise ValueError("The action must belong to the selected DAG and server")
    spec = row["execution_spec"]
    row = dict(row)
    row["execution_spec"] = json.loads(spec) if isinstance(spec, str) else spec
    return row


def action_for_input(structured, cursor=None):
    dag_id = structured.dag_id.strip()
    if not dag_id and structured.dag_source_code.strip():
        # Syntax-only discovery, never import/execute the pasted DAG.
        tree = ast.parse(structured.dag_source_code)
        ids = {kw.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
               for kw in node.keywords if kw.arg == "dag_id" and isinstance(kw.value, ast.Constant)
               and isinstance(kw.value.value, str)}
        if len(ids) == 1:
            dag_id = ids.pop()
    if not dag_id:
        raise ValueError("Enter the DAG/component ID")
    target_id = _target_id(structured.target_registration.model_dump(mode="json"))
    if structured.managed_action is not None:
        if structured.selected_action_id:
            raise ValueError("Choose a new action or an existing action, not both")
        return compile_action(structured.managed_action, dag_id, target_id)
    if not structured.selected_action_id or cursor is None:
        raise ValueError("Create an action or select an existing ACTIVE action")
    return _existing_action(cursor, structured.selected_action_id, dag_id, target_id)


def render_action_sop(action):
    spec = action["execution_spec"]
    checks = spec.get("prechecks") or []
    if not checks:
        raise ValueError("An action needs at least one live health check")
    lines = ["# INVESTIGATION SOP FOR " + action["component_id"], "",
             "Component ID: " + action["component_id"],
             "Operating mode: APPROVAL_REQUIRED_ACTION", "Registered SSH target: " + action["target_id"],
             "Registered action ID: " + action["action_id"],
             "Action version: " + action["implementation_version"], SOP_MARKER, "",
             "Procedure basis: administrator-reviewed action health checks. Pasted DAG source is context; its side effects are not diagnostic steps.", "",
             "Run all required health checks at verification time. Diagnose the current state; historical timestamps are optional context.", ""]
    for index, check in enumerate(checks, 1):
        if check.get("kind") == "http":
            lines += [f"{index}. Run check_http_endpoint on target '{check['url']}'.",
                      "Healthy HTTP status codes: " + ", ".join(map(str, check["expected_status_codes"])) + ".", ""]
        elif check.get("kind") == "command":
            lines += [f"{index}. Run run_ssh_command on target '{action['target_id']}' with this exact command:",
                      "", "```sh", check["command"], "```", "",
                      "Successful exit codes: " + ", ".join(map(str, check.get("expected_exit_codes", [0]))) + ".",
                      "Healthy output (full-string regex): `" + (check.get("healthy_stdout_regex") or "successful nonempty output") + "`.",
                      "Unhealthy output (full-string regex): `" + (check.get("unhealthy_stdout_regex") or "not specified") + "`.",
                      "Explicit unhealthy exit codes: " + ", ".join(map(str, check.get("unhealthy_exit_codes", []))) + ".",
                      "Missing required output or an unexpected exit code is INCONCLUSIVE.", ""]
        else:
            raise ValueError("Unsupported action health check kind")
    lines += [f"{len(checks)+1}. Interpret all required checks:",
              "- Every check healthy: NO_REMEDIATION_REQUIRED; recommended_action is empty.",
              "- A failed transport, BLOCKED, truncated, invalid or ambiguous result: INCONCLUSIVE; recommended_action is empty.",
              "- Otherwise, at least one valid unhealthy result: REMEDIATION_RECOMMENDED; recommended_action must be exactly '" + action["action_id"] + "'. Explain the measured symptom and the reviewed action.",
              "- Apply healthy stdout patterns before unhealthy patterns. Regexes use a full-string match; an unmatched value is INCONCLUSIVE.",
              "- These checks assess current health. They do not establish the historical cause or cover unrelated incident errors.", "",
              "The Verifier never executes the remediation command. An engineer must approve a separate remediation request. The Executor repeats the live checks and skips the action if already healthy; it verifies health afterward. A successful command alone is not recovery."]
    return "\n".join(lines)


def managed_draft(request, database_cursor, response_model):
    structured = request.structured_input
    with database_cursor() as (_, cursor):
        action = action_for_input(structured, cursor)
    exceptions = structured.exception_types
    if not exceptions and structured.dag_source_code.strip():
        from .dag_source_analysis import analyze_dag_source
        exceptions = analyze_dag_source(structured.dag_source_code).exception_types
    if not exceptions:
        raise ValueError("Enter the monitored exception types")
    return response_model.model_validate({
        "assistant_message": "Review the health checks and exact action. Activation registers the action; it does not execute it.",
        "ready_for_review": True, "missing_fields": [], "validation_issues": [],
        "source_plan": {}, "confirmation_questions": [], "explanation_notes": [],
        "action_preview": {**action, "lifecycle_status": "DRAFT" if structured.managed_action else action["lifecycle_status"]},
        "draft": {"schema_version": 1, "lifecycle_status": "DRAFT", "operating_mode": "APPROVAL_REQUIRED_ACTION",
            "dag": {"dag_id": action["component_id"], "exception_types": exceptions,
                    "investigation_sop": render_action_sop(action)},
            "target_registration": structured.target_registration.model_dump(mode="json"),
            "managed_action": structured.managed_action.model_dump(mode="json") if structured.managed_action else None,
            "selected_action_id": action["action_id"], "remediation_action": None,
            "review_template": {"summary": action["description"],
                "sop_review_points": ["Confirm the health check evaluates the condition requiring this action."],
                "action_review_points": ["Review the exact generated catalog command, selected server and execution permissions."],
                "activation_requirements": ["Activation registers an approval-required action. It does not run it."]}}})


def validate_managed_activation(request, cursor):
    draft = request.draft
    if draft.managed_action is not None and (draft.operating_mode != "APPROVAL_REQUIRED_ACTION" or SOP_MARKER not in draft.dag.investigation_sop):
        raise ValueError("Regenerate the managed action and its health-check SOP")
    if draft.operating_mode != "APPROVAL_REQUIRED_ACTION" or SOP_MARKER not in draft.dag.investigation_sop:
        return None
    if not request.action_definition_confirmed:
        raise ValueError("Confirm the reviewed action definition before activation")
    source = request.source_review
    if source is None or source.operating_mode != "APPROVAL_REQUIRED_ACTION":
        raise ValueError("Regenerate the action draft with its reviewed inputs")
    if _json(draft.target_registration.model_dump(mode="json")) != _json(source.target_registration.model_dump(mode="json")):
        raise ValueError("Selected server changed; regenerate the draft")
    if draft.managed_action != source.managed_action:
        raise ValueError("Action definition changed; regenerate the draft")
    action = action_for_input(source, cursor)
    if (draft.dag.dag_id != action["component_id"] or draft.selected_action_id != action["action_id"]
            or draft.dag.investigation_sop.strip() != render_action_sop(action).strip()):
        raise ValueError("Action or SOP changed; regenerate the reviewed draft")
    return action


def register_managed_action(cursor, request, actor):
    action = validate_managed_activation(request, cursor)
    if action is None or request.draft.managed_action is None:
        return
    cursor.execute("SELECT action_id FROM remediation_action_catalog WHERE action_id = %s FOR UPDATE",
                   (action["action_id"],))
    if cursor.fetchone():
        raise ValueError("Action ID already exists. Select that action or use a new ID; existing actions are never overwritten.")
    cursor.execute("""INSERT INTO remediation_action_catalog (
        action_id, component_id, target_id, display_name, description, risk_level,
        lifecycle_status, implementation_version, executor_type, execution_spec,
        verification_summary, rollback_summary, requires_approval, created_by, updated_by
        ) VALUES (%s,%s,%s,%s,%s,%s,'ACTIVE',%s,'SSH_COMMAND',%s,%s,%s,TRUE,%s,%s)""",
        (action["action_id"], action["component_id"], action["target_id"], action["display_name"],
         action["description"], action["risk_level"], action["implementation_version"],
         _json(action["execution_spec"]), action["verification_summary"], action["rollback_summary"], actor, actor))


def prepare_component_update(cursor, request):
    if not request.update_existing_component:
        return False
    if SOP_MARKER not in request.draft.dag.investigation_sop:
        raise ValueError("Existing-component updates require a reviewed execution-mode draft")
    dag_id = request.draft.dag.dag_id
    cursor.execute("SELECT DAG_id FROM t_sops_master WHERE DAG_id = %s FOR UPDATE", (dag_id,))
    rows = cursor.fetchall()
    cursor.execute("SELECT dag_id FROM registered_dags WHERE dag_id = %s FOR UPDATE", (dag_id,))
    dag = cursor.fetchone()
    if len(rows) != 1 or not dag:
        raise ValueError("An existing-component update requires one registered DAG and one SOP. Otherwise onboard as new or repair the registration first.")
    cursor.execute("""SELECT remediation_id FROM remediation_requests
        WHERE component_id_snapshot = %s
        AND status IN ('PENDING_APPROVAL','APPROVED','RUNNING','MANUAL_REVIEW')
        LIMIT 1 FOR UPDATE""", (dag_id,))
    if cursor.fetchone():
        raise ValueError("Finish or cancel the component's active remediation request before changing its action")
    return True


def update_component(cursor, request, exception_types, actor):
    dag = request.draft.dag
    cursor.execute("UPDATE t_sops_master SET investigation_sop = %s WHERE DAG_id = %s",
                   (dag.investigation_sop, dag.dag_id))
    cursor.execute("""UPDATE registered_dags SET operating_mode = %s, exception_types = %s,
        remediation_action_id = %s, lifecycle_status = 'ACTIVE', updated_by = %s WHERE dag_id = %s""",
        (request.draft.operating_mode, json.dumps(exception_types), request.draft.selected_action_id, actor, dag.dag_id))
