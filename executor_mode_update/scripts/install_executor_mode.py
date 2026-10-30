"""Install the admin action mode into an existing RCA project (Python 3.9+).

Preview: python scripts/install_executor_mode.py C:\\path\\to\\rca-agent-dashboard
Apply:   python scripts/install_executor_mode.py C:\\path\\to\\rca-agent-dashboard --apply
All edits are prepared before writes. Existing files are backed up together.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path


VERSION = "RCA_ADMIN_EXECUTION_MODE_V4"
PREVIOUS_VERSION = "RCA_ADMIN_EXECUTION_MODE_V1"
EXTRACTION_VERSION = "RCA_ADMIN_EXECUTION_MODE_V2"
RELATED_VERSION = "RCA_ADMIN_EXECUTION_MODE_V3"


def once(text, old, new, label):
    if text.count(old) != 1:
        raise ValueError("Cannot safely locate " + label + ". No files changed; supply this current file for an integration update.")
    return text.replace(old, new, 1)


def insert_import(text, statement):
    tree = ast.parse(text)
    futures = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == "__future__"]
    index = futures[-1].end_lineno if futures else 0
    lines = text.splitlines(keepends=True)
    lines.insert(index, "\n" + statement + "\n")
    return "".join(lines)


def class_field(text, name, field):
    nodes = [node for node in ast.parse(text).body if isinstance(node, ast.ClassDef) and node.name == name]
    if len(nodes) != 1:
        raise ValueError("Expected schema class missing: " + name)
    node = nodes[0]
    first = node.body[0]
    index = first.end_lineno if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str) else node.lineno
    lines = text.splitlines(keepends=True)
    lines.insert(index, field + "\n")
    return "".join(lines)


def replace_method(text, class_name, method, replacement):
    cls = next(node for node in ast.parse(text).body if isinstance(node, ast.ClassDef) and node.name == class_name)
    funcs = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method]
    lines = text.splitlines(keepends=True)
    if funcs:
        node = funcs[0]
        start = min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1
        lines[start:node.end_lineno] = [replacement + "\n"]
    else:
        lines.insert(cls.end_lineno, "\n" + replacement + "\n")
    return "".join(lines)


def patch_schemas(text):
    expected = {"OnboardingBundleDraft": {"selected_action_id"},
                "OnboardingStructuredInput": {"dag_source_code", "investigation_read_only", "selected_action_id"},
                "OnboardingActivationRequest": {"source_review"}}
    for name, fields in expected.items():
        nodes = [node for node in ast.parse(text).body if isinstance(node, ast.ClassDef) and node.name == name]
        present = {node.target.id for node in nodes[0].body if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)} if nodes else set()
        if not fields.issubset(present):
            raise ValueError("The current source-onboarding schema is required: " + name + " is missing " + ", ".join(sorted(fields - present)))
    text = insert_import(text, "from .managed_actions import ManagedActionInput")
    for name in ("OnboardingBundleDraft", "OnboardingStructuredInput"):
        text = class_field(text, name, "    managed_action: Optional[ManagedActionInput] = None")
    text = class_field(text, "OnboardingActivationRequest", "    action_definition_confirmed: bool = False")
    text = class_field(text, "OnboardingActivationRequest", "    update_existing_component: bool = False")
    text = class_field(text, "OnboardingAssistantResponse", "    action_preview: dict[str, object] = Field(default_factory=dict)")
    text = replace_method(text, "OnboardingStructuredInput", "validate_dag_source_mode", '''    @model_validator(mode="after")
    def validate_dag_source_mode(self) -> "OnboardingStructuredInput":
        if self.dag_source_code.strip() and not self.investigation_read_only:
            raise ValueError("Confirm that Verifier investigations are read-only")
        if self.managed_action is not None:
            if self.operating_mode != "APPROVAL_REQUIRED_ACTION":
                raise ValueError("A new action requires approval-required execution mode")
            if self.selected_action_id is not None:
                raise ValueError("Choose a new action or an existing action")
        if self.dag_source_code.strip() and self.operating_mode == "INVESTIGATE_ONLY" and self.selected_action_id:
            raise ValueError("Investigate-only mode cannot select an action")
        return self''')
    text = replace_method(text, "OnboardingBundleDraft", "validate_managed_action_mode", '''    @model_validator(mode="after")
    def validate_managed_action_mode(self) -> "OnboardingBundleDraft":
        if self.managed_action is not None and (self.operating_mode != "APPROVAL_REQUIRED_ACTION" or self.selected_action_id != self.managed_action.action_id):
            raise ValueError("The action must match the approval-required draft")
        return self''')
    return text


def patch_agent(text):
    text = insert_import(text, "from .managed_actions import managed_draft")
    old = "    structured = request.structured_input\n    if structured is not None and structured.dag_source_code.strip():"
    new = '''    structured = request.structured_input
    if structured is not None and structured.operating_mode == "APPROVAL_REQUIRED_ACTION":
        return managed_draft(request, database_cursor, OnboardingAssistantResponse)
    if structured is not None and structured.dag_source_code.strip():'''
    return once(text, old, new, "onboarding generation entry")


def patch_service(text):
    text = insert_import(text, "from .managed_actions import SOP_MARKER, validate_managed_activation, register_managed_action, prepare_component_update, update_component")
    text = once(text, "    draft = request.draft\n    dag_id = draft.dag.dag_id.strip()", '''    draft = request.draft
    if draft.managed_action is not None or SOP_MARKER in draft.dag.investigation_sop:
        try:
            with database_cursor() as (_, cursor):
                validate_managed_activation(request, cursor)
        except ValueError as exc:
            raise OnboardingValidationError(str(exc)) from exc
    dag_id = draft.dag.dag_id.strip()''', "activation request validation")
    text = once(text, "if request.source_review is not None or is_source_sop(sop):", "if (request.source_review is not None or is_source_sop(sop)) and SOP_MARKER not in sop:", "source-vs-admin SOP validation")
    old = '''            _validate_selected_action(cursor, request, str(target["id"]))
            _insert_new_target(cursor, request, host_key, actor)'''
    new = '''            _insert_new_target(cursor, request, host_key, actor)
            try:
                register_managed_action(cursor, request, actor)
            except ValueError as exc:
                raise OnboardingValidationError(str(exc)) from exc
            _validate_selected_action(cursor, request, str(target["id"]))'''
    text = once(text, old, new, "atomic target and catalog registration")
    text = once(text, "            _assert_dag_available(cursor, request.draft.dag.dag_id)", '''            try:
                component_update = prepare_component_update(cursor, request)
            except ValueError as exc:
                raise OnboardingValidationError(str(exc)) from exc
            if not component_update:
                _assert_dag_available(cursor, request.draft.dag.dag_id)''', "existing component selection")
    text = once(text, "            _insert_dag_records(cursor, request, exception_types, actor)", '''            if component_update:
                update_component(cursor, request, exception_types, actor)
            else:
                _insert_dag_records(cursor, request, exception_types, actor)''', "existing component transaction")
    text = once(text, '        "operating_mode": request.draft.operating_mode,', '        "operating_mode": request.draft.operating_mode,\n        "component_updated": request.update_existing_component,\n        "managed_action_created": request.draft.managed_action is not None,', "action registration audit")
    return text


def patch_executor(text):
    text = insert_import(text, "from .managed_executor_lock import with_target_lock, validate_check_result")
    text = once(text, "def run_registered_action(", "@with_target_lock\ndef run_registered_action(", "executor action function")
    text = once(text, "def run_check(", "@validate_check_result\ndef run_check(", "executor health checks")
    return text


def patch_executor_database(text):
    text = insert_import(text, "from .managed_executor_lock import final_result_status")
    return once(text, '        final_status = "SUCCEEDED" if result["success"] else "FAILED"',
                '        final_status = final_result_status(result)', "uncertain execution result status")


def patch_frontend(text):
    text = once(text, "import { api } from '../services/api.js'", "import { api } from '../services/api.js'\nimport ManagedActionForm from '../components/ManagedActionForm.vue'", "Vue imports")
    text = once(text, "const actions = ref([])", '''const actionSource = ref('NEW')
const managedAction = ref(null)
const actionPreview = ref(null)
const actionDefinitionConfirmed = ref(false)
const updateExistingComponent = ref(false)
const actions = ref([])''', "action state")
    # New definitions have their own admin input; existing definitions stay
    # selected through the original action browser.
    text = once(text, "const selectedActionId = computed(() => {", "const selectedActionId = computed(() => {\n  if (actionSource.value === 'NEW' && form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION') return null", "selected action computation")
    text = once(text, "const structuredInput = computed(() => ({", "const actionComponentId = computed(() => form.value.dagId.trim() || form.value.dagSourceCode.match(/\\bdag_id\\s*=\\s*[\"']([^\"']+)[\"']/)?.[1] || '')\n\nconst structuredInput = computed(() => ({\n  managed_action: form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' && actionSource.value === 'NEW' ? managedAction.value : null,", "structured action input")
    load_start = text.index("async function loadActions()")
    load_end = text.index("function invalidateDraft()", load_start)
    section = text[load_start:load_end].replace("form.value.dagId.trim()", "actionComponentId.value")
    text = text[:load_start] + section + text[load_end:]
    text = once(text, "const bundle = computed(() => ({", "const bundle = computed(() => ({\n  managed_action: form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' && actionSource.value === 'NEW' ? managedAction.value : null,", "bundle action input")
    start = text.index("const bundle = computed(")
    end = text.index("const assistantRequest =", start)
    section = text[start:end]
    section = once(section, "selectedActionId.value,", "(actionSource.value === 'NEW' && form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' ? managedAction.value?.action_id || null : selectedActionId.value),", "bundle action ID")
    text = text[:start] + section + text[end:]
    text = once(text, "const activationRequest = computed(() => ({", "const activationRequest = computed(() => ({\n  update_existing_component: form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' && Boolean(updateExistingComponent.value),\n  action_definition_confirmed: Boolean(actionDefinitionConfirmed.value),", "action confirmation")
    # Both source and manual admin-action drafts are deterministically rebuilt
    # from these inputs at activation.
    text = text.replace("source_review: usesDagSource.value", "source_review: (usesDagSource.value || form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION')")
    text = once(text, '''    if (form.value.operatingMode !== 'INVESTIGATE_ONLY') {
      issues.push('Pasted-DAG onboarding uses investigate-only mode.')
    }''', "", "source mode restriction")
    text = once(text, "!form.value.selectedActionId\n  ) {", "actionSource.value === 'EXISTING' && !form.value.selectedActionId\n  ) {", "action selection requirement")
    text = once(text, "  return [\n    ...new Set(issues),\n  ]\n})\n\nconst activationIssues", '''  if (form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' && actionSource.value === 'NEW') {
    if (!managedAction.value?.action_id || !managedAction.value?.display_name) issues.push('Enter the action ID and display name.')
    if (managedAction.value?.operation !== 'CUSTOM_COMMAND' && !managedAction.value?.process_path) issues.push('Enter the exact script path.')
    if (managedAction.value?.operation !== 'TRIM_PROCESSES' && !managedAction.value?.command) issues.push('Enter the exact action command.')
  }
  return [
    ...new Set(issues),
  ]
})

const activationIssues''', "frontend draft validation")
    text = once(text, "const activationIssues = computed(() => {", "const activationIssues = computed(() => {\n  const actionIssues = form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' && !actionDefinitionConfirmed.value ? ['Confirm the exact action definition.'] : []", "activation checkbox validation")
    text = once(text, "    ...formIssues.value,", "    ...formIssues.value,\n    ...actionIssues,", "activation action issues")
    text = once(text, "    applyDraft(\n      response.draft,\n    )", "    applyDraft(\n      response.draft,\n    )\n    actionPreview.value = response.action_preview || null", "server action preview")
    text = once(text, "sourcePlan.value = response.source_plan || null", "sourcePlan.value = response.source_plan && Object.keys(response.source_plan).length ? response.source_plan : null", "empty source context")
    text = once(text, "function invalidateDraft() {", "function invalidateDraft() {\n  actionDefinitionConfirmed.value = false\n  actionPreview.value = null", "invalidate action approval")
    redacted_start = text.index("const redactedActivationRequest")
    redacted_end = text.index("const formIssues", redacted_start)
    section = text[redacted_start:redacted_end]
    section = once(section, "    return {\n      draft:", "    return {\n      update_existing_component: form.value.operatingMode === 'APPROVAL_REQUIRED_ACTION' && Boolean(updateExistingComponent.value),\n      action_definition_confirmed: Boolean(actionDefinitionConfirmed.value),\n      draft:", "redacted action confirmation")
    text = text[:redacted_start] + section + text[redacted_end:]
    # Show execution options for both source and manual onboarding.
    text = once(text, '<div v-else class="mode-grid">', '<div class="mode-grid">', "mode choices")
    text = once(text, "change data or link a remediation action.", "change data. Remediation is registered separately below.", "mode explanation")
    text = once(text, "Use an existing action\n", "Investigate with approved execution\n", "execution mode label")
    text = once(text, "Link an ACTIVE registered action.\n", "Create a reviewed action or choose an ACTIVE action.\n", "execution mode description")
    text = once(text, '''          <div
            v-if="
              !usesDagSource &&''', '''          <div
            v-if="''', "investigate-only notice")
    text = once(text, '''          <div
            v-else-if="!usesDagSource"
            class="action-browser"''', '''          <section v-if="form.operatingMode === 'APPROVAL_REQUIRED_ACTION'">
            <div class="mode-grid">
              <label><input v-model="actionSource" type="radio" value="NEW" /><span>Create a new action</span></label>
              <label><input v-model="actionSource" type="radio" value="EXISTING" /><span>Choose an existing action</span></label>
            </div>
            <ManagedActionForm v-if="actionSource === 'NEW'" v-model="managedAction" :component-id="actionComponentId" />
            <p v-if="form.targetMode === 'NEW'" class="notice">The server from Step 2 is reused. <button type="button" class="button secondary compact" @click="goTo(2)">Check Executor credentials</button></p>
          </section>
          <div
            v-if="form.operatingMode === 'APPROVAL_REQUIRED_ACTION' && actionSource === 'EXISTING'"
            class="action-browser"''', "new action form")
    text = once(text, '''        <template v-else>
          <header class="section-heading">''', '''        <template v-else>
          <section v-if="actionPreview && form.operatingMode === 'APPROVAL_REQUIRED_ACTION'" class="notice">
            <h3>Review the registered action</h3>
            <p>{{ actionPreview.display_name }} · {{ actionPreview.risk_level }} · Server: {{ actionPreview.target_id }}</p>
            <p>Activation saves the action. It does not execute it. Each execution needs incident approval.</p>
            <details><summary>Exact command and health checks</summary><pre style="white-space: pre-wrap; overflow-wrap: anywhere">{{ JSON.stringify(actionPreview.execution_spec, null, 2) }}</pre></details>
            <label class="confirmation"><input v-model="actionDefinitionConfirmed" type="checkbox" /><span>I reviewed this action, its server, health checks and execution permissions.</span></label>
            <details><summary>Already registered?</summary><label class="confirmation"><input v-model="updateExistingComponent" type="checkbox" /><span>Update this existing component's SOP and action link. Existing catalog actions and incident history are kept.</span></label></details>
          </section>
          <header class="section-heading">''', "final action review")
    # When switching to action mode, keep the safe read-only diagnostic
    # acknowledgement but do not force the entire component to read-only mode.
    return text


def upgrade_schemas(text):
    text=class_field(text,"OnboardingStructuredInput","    extract_action_candidates: bool = False")
    text=class_field(text,"OnboardingAssistantResponse","    action_extraction: dict[str, object] = Field(default_factory=dict)")
    return once(text,'if self.dag_source_code.strip() and not self.investigation_read_only:',
                'if self.dag_source_code.strip() and not self.investigation_read_only and not self.extract_action_candidates:',
                'syntax-only action extraction policy')


def upgrade_agent(text):
    text=once(text,'from .managed_actions import managed_draft','from .managed_actions import managed_draft, extraction_draft','action extractor import')
    return once(text,'    structured = request.structured_input\n    if structured is not None and structured.operating_mode == "APPROVAL_REQUIRED_ACTION":',
                '    structured = request.structured_input\n    if structured is not None and structured.extract_action_candidates:\n        return extraction_draft(request, OnboardingAssistantResponse)\n    if structured is not None and structured.operating_mode == "APPROVAL_REQUIRED_ACTION":',
                'action extraction entry')


def upgrade_frontend(text):
    text=once(text,':component-id="actionComponentId" />',':component-id="actionComponentId" :source-input="structuredInput" @runtime-value="setActionRuntimeValue" />','source input in action form')
    text=once(text,'const actionComponentId = computed(','''function setActionRuntimeValue({ key, value }) {
  let encoded
  try { encoded = JSON.stringify(JSON.parse(value)) } catch { encoded = JSON.stringify(value) }
  airflowVariableValues.value = { ...airflowVariableValues.value, [key]: encoded }
}

const actionComponentId = computed(''','deployed action variable values')
    text=once(text,"managedAction.value?.operation !== 'TRIM_PROCESSES' && !managedAction.value?.command",
              "['RESTART_SCRIPT', 'CUSTOM_COMMAND'].includes(managedAction.value?.operation) && !managedAction.value?.command",'stop action form completeness')
    return text


def upgrade_linked_schemas(text):
    text=class_field(text,'OnboardingStructuredInput','    related_dag_sources: dict[str, str] = Field(default_factory=dict, max_length=8)')
    return replace_method(text,'OnboardingStructuredInput','validate_related_sources','''    @model_validator(mode="after")
    def validate_related_sources(self) -> "OnboardingStructuredInput":
        if any(not key.strip() or len(key) > 255 or len(source) > 150000 for key, source in self.related_dag_sources.items()):
            raise ValueError("Paste one related DAG per field, up to 150,000 characters each")
        if sum(len(source) for source in self.related_dag_sources.values()) > 600000:
            raise ValueError("Related DAG source exceeds the 600,000-character review limit")
        return self''')


def upgrade_linked_frontend(text):
    text=once(text,'const managedAction = ref(null)','const managedAction = ref(null)\nconst relatedDagSources = ref({})','related DAG source state')
    text=once(text,'function setActionRuntimeValue(','''function setRelatedDagSource({ dagId, source }) {
  relatedDagSources.value = { ...relatedDagSources.value, [dagId]: source }
}

function setActionRuntimeValue(''','related DAG source updates')
    text=once(text,'const structuredInput = computed(() => ({','const structuredInput = computed(() => ({\n  related_dag_sources: relatedDagSources.value,','related source request')
    return once(text,'@runtime-value="setActionRuntimeValue" />','@runtime-value="setActionRuntimeValue" @related-source="setRelatedDagSource" />','related source form event')


def prepare(root):
    payload = Path(__file__).resolve().parents[1]
    files = {}
    targets = {
        "backend/app/schemas.py": patch_schemas,
        "backend/app/onboarding_agent.py": patch_agent,
        "backend/app/onboarding_service.py": patch_service,
        "frontend/src/views/AdminOnboardingView.vue": patch_frontend,
    }
    executors = [p for p in ("agents/executor.py", "agents/remediation_executor.py")
                 if (root / p).is_file() and "def run_registered_action(" in (root / p).read_text(encoding="utf-8-sig")]
    if len(executors) != 1:
        raise ValueError("Locate the current database-backed executor with run_registered_action before installing")
    registry = root / "agents/action_registry.py"
    if not registry.is_file() or "def action_from_catalog_row(" not in registry.read_text(encoding="utf-8-sig"):
        raise ValueError("The existing database-backed catalog action_registry.py is required")
    targets[executors[0]] = patch_executor
    databases = [p for p in ("agents/database.py", "agents/remediation_database.py")
                 if (root / p).is_file() and "class RemediationDatabase" in (root / p).read_text(encoding="utf-8-sig")]
    if len(databases) != 1:
        raise ValueError("Locate the current RemediationDatabase module before installing")
    targets[databases[0]] = patch_executor_database
    upgrades={"backend/app/schemas.py":upgrade_schemas,"backend/app/onboarding_agent.py":upgrade_agent,
              "frontend/src/views/AdminOnboardingView.vue":upgrade_frontend}
    linked_upgrades={'backend/app/schemas.py':upgrade_linked_schemas,
                     'frontend/src/views/AdminOnboardingView.vue':upgrade_linked_frontend}
    for relative, transform in targets.items():
        path = root / relative
        if not path.is_file():
            raise ValueError("Required application file missing: " + relative)
        text = path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
        if VERSION in text:
            raise ValueError("Execution mode is already installed in " + relative)
        if RELATED_VERSION in text:
            if relative!='backend/app/schemas.py':
                continue
            updated=text
        elif EXTRACTION_VERSION in text:
            if relative not in linked_upgrades:
                continue
            updated=text
        elif PREVIOUS_VERSION in text:
            if relative not in upgrades:
                continue
            updated=upgrades[relative](text)
        else:
            updated = transform(text)
            if relative in upgrades:
                updated=upgrades[relative](updated)
        if relative in linked_upgrades and RELATED_VERSION not in text:
            updated=linked_upgrades[relative](updated)
        if path.suffix == ".py":
            compile(updated, str(path), "exec")
            updated += "\n# " + VERSION + "\n"
        else:
            updated += "\n<!-- " + VERSION + " -->\n"
        files[relative] = updated.encode("utf-8")
    for relative in ("backend/app/managed_actions.py", "backend/app/managed_process.py", "backend/app/action_candidates.py",
                     "frontend/src/components/ManagedActionForm.vue"):
        files[relative] = (payload / relative).read_bytes()
    files["agents/managed_executor_lock.py"] = (payload / "backend/app/managed_executor_lock.py").read_bytes()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.project_root.resolve()
    try:
        files = prepare(root)
    except (ValueError, SyntaxError, StopIteration) as exc:
        parser.exit(2, "Stopped before writes: " + str(exc) + "\n")
    print("Prepared execution mode update:")
    for relative in files:
        print("  " + relative)
    if not args.apply:
        print("Preview only. Run again with --apply. No database changes or production commands were run.")
        return
    backup = root / ("executor_mode_backup_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    backup.mkdir()
    manifest = []
    # Backup every destination before writing the first change.
    for relative, content in files.items():
        destination = root / relative
        exists = destination.exists()
        if exists:
            saved = backup / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination, saved)
        manifest.append({"path": relative, "existed": exists,
                         "installed_sha256": hashlib.sha256(content).hexdigest()})
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    written = []
    try:
        for relative, content in files.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temp = tempfile.mkstemp(dir=destination.parent, prefix="rca-action-")
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                if destination.exists():
                    shutil.copymode(destination, temp)
                os.replace(temp, destination)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
            written.append(relative)
    except Exception:
        for relative in reversed(written):
            saved = backup / relative
            if saved.exists():
                shutil.copy2(saved, root / relative)
            else:
                (root / relative).unlink(missing_ok=True)
        raise
    print("Installed. Backup: " + str(backup))
    print("Restart backend, frontend and executor. The pipeline Verifier stays read-only.")


if __name__ == "__main__":
    main()
