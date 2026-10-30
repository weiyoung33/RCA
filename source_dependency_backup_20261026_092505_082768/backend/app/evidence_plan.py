"""Build a source-cited onboarding plan without running pasted Python.

Only bounded literal construction is resolved. Runtime expressions stay visible
as source expressions; they are never evaluated here or rewritten by the LLM.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
import re
import shlex
import textwrap
from dataclasses import dataclass, field
from typing import Any

try:
    from .dag_source_analysis import analyze_dag_source, is_read_only_select
    from .source_command_analysis import is_read_only_ssh_command
except ImportError:
    from dag_source_analysis import analyze_dag_source, is_read_only_select
    from source_command_analysis import is_read_only_ssh_command


@dataclass
class Value:
    text: str
    known: bool = False
    value: Any = None
    evidence: set[str] = field(default_factory=set)
    diagnostics: set[str] = field(default_factory=set)
    variables: set[str] = field(default_factory=set)
    connections: set[str] = field(default_factory=set)
    unknown_inputs: set[str] = field(default_factory=set)
    excluded_dependencies: set[str] = field(default_factory=set)


def call_name(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""


def _bind_select_parameters(query: str, parameters: Value | None) -> str | None:
    """Resolve confirmed positional SQL values, never SQL syntax or identifiers.

    The Verifier accepts one exact SELECT string rather than driver bindings.
    Only literal, bounded values are rendered as SQL literals. Unconfirmed
    values, ambiguous placeholder locations and mismatched arity stay blocked.
    """
    if parameters is None:
        return None if re.search(r"%s|%\([^)]+\)s|\?", query) else query
    if (not parameters.known or type(parameters.value) not in (tuple, list)
            or not 1 <= len(parameters.value) <= 20):
        return None
    literals: list[str] = []
    for value in parameters.value:
        if type(value) is int:
            literals.append(str(value))
        elif type(value) is float and math.isfinite(value):
            literals.append(repr(value))
        elif type(value) is str and re.fullmatch(r"[A-Za-z0-9_ .:/@+-]{1,128}", value):
            literals.append("'" + value + "'")
        else:
            return None

    output: list[str] = []
    quote = ""
    index = 0
    bound = 0
    while index < len(query):
        char = query[index]
        if quote:
            if char == "\\" and quote != "`":
                output.append(query[index:index + 2])
                index += 2
                continue
            if char == quote:
                if index + 1 < len(query) and query[index + 1] == quote:
                    output.append(query[index:index + 2])
                    index += 2
                    continue
                quote = ""
            if query.startswith("%s", index) or char == "?":
                return None
            output.append(char)
        elif char in "'\"`":
            quote = char
            output.append(char)
        elif query.startswith(("--", "/*", "#", "%%", "%(", "?"), index):
            return None
        elif query.startswith("%s", index):
            if bound >= len(literals):
                return None
            # Driver parameters cannot stand for a table identifier. Keep
            # dynamic FROM/JOIN targets outside the automatic investigation.
            if re.search(r"\b(?:FROM|JOIN)\s*$", "".join(output), re.IGNORECASE):
                return None
            output.append(literals[bound])
            bound += 1
            index += 2
            continue
        else:
            output.append(char)
        index += 1
    if quote or bound != len(literals):
        return None
    return "".join(output)


class PlanBuilder:
    def __init__(self, source: str, target: dict, variable_values: dict, mappings: dict,
                 external_script_policy: str = "EXCLUDE"):
        if external_script_policy not in {"EXCLUDE", "REVIEW"}:
            raise ValueError("Unknown external script policy")
        self.external_script_policy = external_script_policy
        self.external_operations: list[dict] = []
        self.source = source
        self.tree = ast.parse(source)
        self.target = target
        self.supplied_variables = variable_values
        self.mappings = mappings
        self.evidence: dict[str, dict] = {}
        self.diagnostics: list[dict] = []
        self.rules: list[dict] = []
        self.thresholds: list[dict] = []
        self.variables: dict[str, dict] = {}
        self.connections: dict[str, dict] = {}
        self.required_variables: set[str] = set()
        self.required_connections: set[str] = set()
        self.active_conditions: tuple = ()
        self.unknowns: list[dict] = []
        self.pending_queries: dict[str, Value] = {}
        self.operations = 0
        self.import_aliases = {alias.asname or alias.name: alias.name
                               for statement in self.tree.body if isinstance(statement, ast.ImportFrom)
                               for alias in statement.names}
        # Only these imported operations are known symbolic transformations.
        # They are never invoked on source/runtime data during onboarding.
        self.parser_imports: dict[str, tuple[str, ast.AST]] = {}
        for statement in self.tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    self.parser_imports[alias.asname or alias.name.split('.')[0]] = (alias.name, statement)
            elif isinstance(statement, ast.ImportFrom) and not statement.level:
                for alias in statement.names:
                    self.parser_imports[alias.asname or alias.name] = (f"{statement.module}.{alias.name}", statement)
        functions = {node.name: node for node in self.tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.defined_functions = set(functions)
        roots = [node for node in self.tree.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        self.reachable = {call_name(node.func) for root in roots for node in ast.walk(root) if isinstance(node, ast.Call)}
        while True:
            expanded = self.reachable | {call_name(node.func) for name in self.reachable if name in functions
                                         for node in ast.walk(functions[name]) if isinstance(node, ast.Call)}
            if expanded == self.reachable:
                break
            self.reachable = expanded

    def cite(self, node: ast.AST, kind: str) -> str:
        start, end = node.lineno, getattr(node, "end_lineno", node.lineno)
        key = f"{kind}:{start}:{node.col_offset}:{end}:{getattr(node, 'end_col_offset', 0)}"
        self.evidence.setdefault(key, {
            "id": key, "kind": kind, "start_line": start, "end_line": end,
            "source": ast.get_source_segment(self.source, node) or ast.unparse(node),
        })
        return key

    def unknown(self, node: ast.AST, reason: str, code: str = "SOURCE_UNRESOLVED"):
        # Only explicitly typed coverage gaps can be acknowledged. New warning
        # kinds remain blocking by default; prose never grants an override.
        item = {"reason": reason, "code": code,
                "evidence_ids": [self.cite(node, "unknown")]}
        if item not in self.unknowns:
            self.unknowns.append(item)

    def merged(self, text: str, values: list[Value]) -> Value:
        result = Value(text)
        for value in values:
            for name in ("evidence", "diagnostics", "variables", "connections", "unknown_inputs", "excluded_dependencies"):
                getattr(result, name).update(getattr(value, name))
        return result

    def expression(self, node: ast.AST, env: dict[str, Value]) -> Value:
        text = ast.unparse(node)
        if isinstance(node, ast.Constant):
            return Value(text, True, node.value)
        if isinstance(node, ast.Name):
            if node.id in env:
                return copy.deepcopy(env[node.id])
            value = Value(text)
            if self.import_aliases.get(node.id, node.id) not in {"Variable", "SSHHook", "BaseHook", "datetime", "date", "timedelta"}:
                value.unknown_inputs.add(node.id)
            return value
        if isinstance(node, ast.Subscript):
            base, index = self.expression(node.value, env), self.expression(node.slice, env)
            result = self.merged(text, [base, index])
            # Resolve data selection only from bounded built-in literals.
            # Runtime rows/stdout and slices remain symbolic expressions.
            if base.known and index.known and type(base.value) in (dict, list, tuple, str) and type(index.value) in (str, int):
                try:
                    result.value = base.value[index.value]
                    result.known = True
                    result.evidence.add(self.cite(node, "literal_selection"))
                except (KeyError, IndexError, TypeError):
                    result.unknown_inputs.add("invalid literal selection " + text)
            return result
        if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
            local, values = copy.deepcopy(env), []
            for generator in node.generators:
                iterable = self.expression(generator.iter, local)
                values.append(iterable)
                element = copy.deepcopy(iterable)
                element.known = False
                self.bind(generator.target, element, local)
                values += [self.expression(test, local) for test in generator.ifs]
            values += [self.expression(part, local) for part in
                       ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt])]
            return self.merged(text, values)
        if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
            parts = (node.elts if not isinstance(node, ast.Dict)
                     else [part for pair in zip(node.keys, node.values) for part in pair if part])
            values = [self.expression(part, env) for part in parts]
            result = self.merged(text, values)
            if len(values) <= 100 and all(v.known for v in values):
                result.known = True
                data = [v.value for v in values]
                try:
                    result.value = (dict(zip(data[::2], data[1::2])) if isinstance(node, ast.Dict)
                                    else tuple(data) if isinstance(node, ast.Tuple) else data)
                except (TypeError, ValueError):
                    result.known = False
            return result
        if isinstance(node, ast.JoinedStr):
            values, pieces = [], []
            for part in node.values:
                value = self.expression(part.value if isinstance(part, ast.FormattedValue) else part, env)
                values.append(value)
                if value.known and type(value.value) in (str, int, float) and not (
                    isinstance(part, ast.FormattedValue) and (part.format_spec or part.conversion != -1)
                ):
                    pieces.append(str(value.value))
                else:
                    pieces.append(None)
            result = self.merged(text, values)
            if all(p is not None for p in pieces):
                result.known, result.value = True, "".join(pieces)
            return result
        if isinstance(node, ast.BinOp):
            left, right = self.expression(node.left, env), self.expression(node.right, env)
            result = self.merged(text, [left, right])
            # Resolve literal string construction only, never runtime arithmetic.
            if isinstance(node.op, ast.Add) and left.known and right.known and isinstance(left.value, str) and isinstance(right.value, str):
                result.known, result.value = True, left.value + right.value
            return result
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            value = self.expression(node.operand, env)
            if value.known and type(value.value) in (int, float):
                value.value, value.text = -value.value, text
            return value
        if isinstance(node, ast.Compare):
            operands = [self.expression(part, env) for part in [node.left, *node.comparators]]
            result = self.merged(text, operands)
            if all(part.known for part in operands):
                checks = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
                          ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
                          ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b}
                try:
                    if all(type(op) in checks for op in node.ops):
                        result.known, result.value = True, all(checks[type(op)](left.value, right.value)
                            for left, op, right in zip(operands, node.ops, operands[1:]))
                except TypeError:
                    result.unknown_inputs.add("incompatible confirmed types in " + text)
            return result
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            if isinstance(node.func, ast.Name):
                name = self.import_aliases.get(name, name)
            args = [self.expression(arg, env) for arg in node.args]
            args += [self.expression(kw.value, env) for kw in node.keywords]
            imported_parser = self.parser_binding(node.func, env)
            base = Value("") if imported_parser else self.expression(node.func.value, env) if isinstance(node.func, ast.Attribute) else Value("")
            result = self.merged(text, [base, *args])
            if imported_parser:
                result.evidence.add(self.cite(imported_parser, "import"))
                result.evidence.add(self.cite(node, "transformation"))
                # Retain dependencies and the exact parsing expression; do
                # not execute literal_eval or assume its runtime input valid.
                return result
            if (
                isinstance(node.func, ast.Attribute) and node.func.attr == "literal_eval"
                or isinstance(node.func, ast.Name) and self.parser_imports.get(node.func.id, ("",))[0] == "ast.literal_eval"
            ):
                result.unknown_inputs.add("unverified parser binding " + ast.unparse(node.func))
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "append", "extend", "insert", "pop", "remove", "clear", "update",
                "setdefault", "sort", "reverse", "__setitem__", "__delitem__",
            }:
                self.invalidate_container(node.func.value, result, env)
            if name == "get" and isinstance(node.func, ast.Attribute) and self.import_aliases.get(ast.unparse(node.func.value), ast.unparse(node.func.value)) == "Variable":
                if not args or not args[0].known or not isinstance(args[0].value, str):
                    result.unknown_inputs.add("unresolved Airflow Variable name")
                    result.evidence.add(self.cite(node, "airflow_variable"))
                    return result
                key = args[0].value
                evidence_id = self.cite(node, "airflow_variable")
                metadata = self.variables.setdefault(key, {"name": key, "evidence_ids": [], "confirmed": False})
                if evidence_id not in metadata["evidence_ids"]:
                    metadata["evidence_ids"].append(evidence_id)
                result.evidence.add(evidence_id)
                result.variables.add(key)
                supplied = self.supplied_variables.get(key)
                if supplied is not None:
                    try:
                        decoded = json.loads(supplied)
                        if not isinstance(decoded, (str, int, float, bool, list, dict, type(None))):
                            raise ValueError()
                        if isinstance(decoded, float) and not math.isfinite(decoded):
                            raise ValueError()
                        deserialize = next((kw.value for kw in node.keywords if kw.arg == "deserialize_json"), None)
                        as_json = isinstance(deserialize, ast.Constant) and deserialize.value is True
                        result.known = True
                        result.value = decoded if as_json or isinstance(decoded, str) else json.dumps(decoded)
                        metadata.update(confirmed=True, value=decoded)
                    except (TypeError, ValueError):
                        metadata["error"] = "Enter a valid JSON value, for example 15 or \"host.example\"."
                return result
            # Connection names are evidence, never inferred hostnames.
            connection_nodes = []
            if name == "SSHHook":
                connection_nodes = [kw.value for kw in node.keywords if kw.arg == "ssh_conn_id"]
            elif name == "SSHOperator":
                connection_nodes = [kw.value for kw in node.keywords if kw.arg == "ssh_conn_id"]
            elif name in {"get_connection", "init_db_proj"} and node.args:
                connection_nodes = [node.args[0]]
            for connection_node in connection_nodes:
                connection = self.expression(connection_node, env)
                if connection.known and isinstance(connection.value, str):
                    key = connection.value
                    evidence_id = self.cite(node, "connection")
                    source_type = "SSH" if name in {"SSHHook", "SSHOperator"} else "DATABASE" if name == "init_db_proj" else "UNKNOWN"
                    metadata = self.connections.setdefault(key, {"id": key, "evidence_ids": [evidence_id], "type": source_type})
                    if metadata["type"] == "UNKNOWN":
                        metadata["type"] = source_type
                    elif metadata["type"] != source_type and source_type != "UNKNOWN":
                        self.unknown(node, "The same source connection is used with different connection types; review its declared identity.")
                    if evidence_id not in metadata["evidence_ids"]:
                        metadata["evidence_ids"].append(evidence_id)
                    result.connections.add(key)
                    result.evidence.add(evidence_id)
                else:
                    result.unknown_inputs.add("unresolved source connection identifier")
                    result.evidence.add(self.cite(node, "connection"))
            if name == "format" and base.known and isinstance(base.value, str) and all(arg.known for arg in args):
                # Only simple replacement fields; no attribute/index access.
                import string
                fields = [part for part in string.Formatter().parse(base.value) if part[1] is not None]
                if all(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*|[0-9]*", part[1]) and not part[2] and not part[3] for part in fields):
                    try:
                        positional = [self.expression(arg, env).value for arg in node.args]
                        keywords = {kw.arg: self.expression(kw.value, env).value for kw in node.keywords if kw.arg}
                        result.known, result.value = True, base.value.format(*positional, **keywords)
                    except (TypeError, ValueError, KeyError, IndexError):
                        pass
            if name in {"exec_command", "run_ssh_command", "execute", "SSHOperator"}:
                sql_keywords = {"command", "query", "sql", "operation"}
                if (name == "execute" and not node.args
                        and not any(kw.arg in sql_keywords for kw in node.keywords)):
                    # Airflow operators commonly use .execute(context=...).
                    # With no SQL argument this is not a database diagnostic;
                    # never reproduce the operator invocation as a Verifier tool.
                    return result
                if name == "execute":
                    self.pending_queries.pop(ast.unparse(node.func.value), None)
                operation_node = next((kw.value for kw in node.keywords if kw.arg in sql_keywords), None)
                operation = self.expression(operation_node, env) if operation_node else args[0] if args else None
                if name == "execute" and operation and operation.known and isinstance(operation.value, str) and not operation.value.lstrip().upper().startswith("SELECT"):
                    # Production writes never enter the diagnostic plan.
                    return result
                # External implementation is outside the supplied source. It
                # can be excluded from executable investigation without being
                # treated as a missing configuration value or authorized tool.
                if name != "execute" and operation and operation.known and isinstance(operation.value, str):
                    try:
                        parts = shlex.split(operation.value.strip())
                    except ValueError:
                        parts = []
                    interpreter = parts[0].replace('\\', '/').rsplit('/', 1)[-1].casefold() if parts else ""
                    if re.fullmatch(r"python(?:[0-9.]+)?(?:\.exe)?", interpreter):
                        ref = self.cite(node, "external_operation")
                        operation_id = "external_" + hashlib.sha256((ref + '\0' + operation.value.strip()).encode()).hexdigest()[:16]
                        external = {
                            "id": operation_id, "operation": operation.value.strip(),
                            "status": "EXCLUDED" if self.external_script_policy == "EXCLUDE" else "REVIEW_REQUIRED",
                            "connection_ids": sorted(result.connections),
                            "evidence_ids": sorted({ref, *result.evidence}),
                            "reason": "External implementation is outside the supplied DAG; this operation is not an authorized diagnostic.",
                        }
                        if external not in self.external_operations:
                            self.external_operations.append(external)
                        result.evidence.add(ref)
                        result.excluded_dependencies.add(operation_id)
                        if self.external_script_policy == "REVIEW":
                            self.required_variables.update(result.variables)
                            self.required_connections.update(result.connections)
                            self.unknown(node, "External Python execution is outside this source-only investigation. Exclude it using the external-script setting or use a separately reviewed diagnostic: " + json.dumps(operation.value.strip()) + ".")
                        return result
                # Only inputs that flow into a diagnostic, its target binding,
                # or its eligibility guards need administrator confirmation.
                # Notification/logging arguments are not diagnostic sinks.
                self.required_variables.update(result.variables)
                self.required_connections.update(result.connections)
                for _, guard in self.active_conditions:
                    self.required_variables.update(guard.variables)
                    result.excluded_dependencies.update(guard.excluded_dependencies)
                if operation is None or not operation.known or not isinstance(operation.value, str):
                    expression = ast.unparse(operation_node) if operation_node is not None else (
                        ast.unparse(node.args[0]) if node.args else "missing command argument"
                    )
                    self.unknown(node,
                        f"An executable diagnostic at source line {node.lineno} has unresolved runtime text "
                        f"in {expression[:160]!r}; review that command expression and its inputs.")
                    return result
                tool = "query_database" if name == "execute" else "run_ssh_command"
                command = operation.value.strip().removesuffix(";").strip() if tool == "query_database" else operation.value.strip()
                if len(command) > 16000:
                    self.unknown(node, "An expanded diagnostic exceeds the supported operation size.")
                    return result
                if tool == "query_database":
                    parameter_value = args[1] if len(node.args) == 2 else None
                    bound = (_bind_select_parameters(command, parameter_value)
                             if len(node.args) <= 2 and not node.keywords else None)
                    if bound is None:
                        self.unknown(node, "Parameterized SQL requires an explicit supported parameter binding; placeholders must not become an executable query.")
                        return result
                    command = bound
                approved = is_read_only_select(command) if tool == "query_database" else is_read_only_ssh_command(command)
                if not approved:
                    self.unknown(node, "A source operation is outside the approved read-only diagnostic policy.")
                    return result
                source_id = self.cite(node, "diagnostic")
                did = "check_" + str(len(self.diagnostics) + 1)
                item = {
                    "id": did, "tool": tool, "operation": command,
                    "target_id": self.target["id"],
                    "connection_ids": sorted(result.connections),
                    "evidence_ids": sorted({source_id, *result.evidence}),
                    "variable_names": sorted(result.variables),
                    "excluded_dependency_ids": sorted(result.excluded_dependencies),
                }
                self.diagnostics.append(item)
                result.evidence.add(source_id)
                result.diagnostics.add(did)
                if name == "execute":
                    self.pending_queries[ast.unparse(node.func.value)] = copy.deepcopy(result)
                return result
            if name in {"fetchone", "fetchall"}:
                pending = self.pending_queries.get(ast.unparse(node.func.value))
                if pending:
                    result = self.merged(text, [result, pending])
            if name in {"int", "float", "str"} and len(args) == 1 and args[0].known:
                try:
                    result.value = {"int": int, "float": float, "str": str}[name](args[0].value)
                    result.known = True
                except (TypeError, ValueError, OverflowError):
                    if args[0].variables:
                        result.unknown_inputs.add("invalid source conversion for " + ", ".join(sorted(args[0].variables)))
            if name == "items" and base.known and isinstance(base.value, dict):
                result.known, result.value = True, list(base.value.items())
            return result
        # Preserve comprehension, slicing, parsing and calculations as source
        # evidence. They are required instructions, not invented SQL semantics.
        values = [self.expression(child, env) for child in ast.iter_child_nodes(node)
                  if isinstance(child, ast.expr)]
        return self.merged(text, values)

    def parser_binding(self, function: ast.AST, env: dict[str, Value]) -> ast.AST | None:
        """Recognize a source-imported parser, not an identically named object."""
        if isinstance(function, ast.Name):
            root, suffix = function.id, ""
        elif isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            root, suffix = function.value.id, "." + function.attr
        else:
            return None
        imported = self.parser_imports.get(root)
        if root in env or root in self.defined_functions or imported is None:
            return None
        qualified, declaration = imported
        return declaration if qualified + suffix == "ast.literal_eval" else None

    def invalidate_container(self, target: ast.AST, value: Value, env: dict[str, Value]):
        """Do not resolve a literal container after unsupported mutation."""
        while isinstance(target, (ast.Subscript, ast.Attribute)):
            target = target.value
        if isinstance(target, ast.Name) and target.id in env:
            updated = self.merged(target.id, [env[target.id], value])
            env[target.id] = updated

    def bind(self, target: ast.AST, value: Value, env: dict[str, Value]):
        if isinstance(target, ast.Name):
            env[target.id] = copy.deepcopy(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, item in enumerate(target.elts):
                member = copy.deepcopy(value)
                if value.known and isinstance(value.value, (list, tuple)) and len(value.value) == len(target.elts):
                    member.value = value.value[index]
                else:
                    member.known = False
                self.bind(item, member, env)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            self.invalidate_container(target, value, env)

    def predicate(self, node: ast.AST, env: dict[str, Value]) -> tuple[str, Value]:
        value = self.expression(node, env)
        for comparison in (item for item in ast.walk(node) if isinstance(item, ast.Compare)):
            for operand in [comparison.left, *comparison.comparators]:
                bound = self.expression(operand, env)
                if bound.known and type(bound.value) in (int, float):
                    record = {"name": ast.unparse(operand), "value": bound.value, "role": "comparison_bound",
                              "evidence_ids": sorted({self.cite(node, "predicate"), *bound.evidence})}
                    if record not in self.thresholds:
                        self.thresholds.append(record)
        clone = copy.deepcopy(node)
        class Constants(ast.NodeTransformer):
            def visit_Name(inner, name):
                bound = env.get(name.id)
                if bound and bound.known and type(bound.value) in (str, int, float, bool, type(None)):
                    return ast.copy_location(ast.Constant(bound.value), name)
                return name
        clone = Constants().visit(clone)
        return ast.unparse(clone), value

    @staticmethod
    def contains_alert(statements: list[ast.stmt]) -> bool:
        for statement in statements:
            for node in ast.walk(statement):
                if isinstance(node, ast.Call) and call_name(node.func) == "insert_job_log_alert":
                    return True
                if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and call_name(node.exc.func).endswith("AlertException"):
                    return True
        return False

    def add_rule(self, node, conditions, outcome, env):
        values = [value for _, value in conditions]
        combined = self.merged("", values)
        if combined.excluded_dependencies:
            self.unknown(node, "A classification branch depends on excluded external output. Its condition remains source evidence; it cannot establish health from the remaining diagnostics alone.", "EXCLUDED_OUTPUT_COVERAGE")
            return
        self.required_variables.update(combined.variables)
        if combined.unknown_inputs:
            self.unknown(node, "A classification rule depends on unresolved source names: " + ", ".join(sorted(combined.unknown_inputs)) + ". Its conclusion is unavailable; the independent approved diagnostics can still collect observations.", "UNRESOLVED_RULE_COVERAGE")
            # Do not render an unresolved predicate as an executable decision.
            # Missing variables still produce configuration questions; unknown
            # text in diagnostic commands remains a separate hard blocker.
            return
        if not combined.diagnostics:
            self.unknown(node, "An alert branch has no statically traced diagnostic output; its measurement provenance needs review.", "UNTRACED_ALERT_COVERAGE")
            return
        rid = "rule_" + str(len(self.rules) + 1)
        self.rules.append({
            "id": rid, "outcome": outcome,
            "condition": " and ".join(f"({text})" for text, _ in conditions),
            "diagnostic_ids": sorted(combined.diagnostics),
            "evidence_ids": sorted({self.cite(node, "rule"), *combined.evidence}),
            "variable_names": sorted(combined.variables),
        })

    def statements(self, statements, env, conditions=()):
        for node in statements:
            self.active_conditions = conditions
            self.operations += 1
            if self.operations > 5000 or len(self.diagnostics) > 100:
                raise ValueError("The source expands beyond the bounded onboarding analysis limit.")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name not in self.reachable:
                    continue
                local = copy.deepcopy(env)
                pending = self.pending_queries
                self.pending_queries = {}
                for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                    local.pop(arg.arg, None)
                self.statements(node.body, local)
                self.pending_queries = pending
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = self.expression(node.value, env)
                evidence_id = self.cite(node, "assignment")
                value.evidence.add(evidence_id)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(node, ast.AugAssign):
                    value = self.merged(ast.unparse(node), [value, self.expression(node.target, env)])
                for target in targets:
                    self.bind(target, value, env)
                    if value.known and type(value.value) in (int, float):
                        record = {"name": ast.unparse(target), "value": value.value, "role": "source_numeric_setting", "evidence_ids": sorted(value.evidence)}
                        if record not in self.thresholds:
                            self.thresholds.append(record)
            elif isinstance(node, ast.Expr):
                self.expression(node.value, env)
                # Track evidence through list accumulation without evaluating it.
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr in {"append", "extend"}:
                    owner = node.value.func.value
                    if isinstance(owner, ast.Name):
                        result = self.merged(ast.unparse(node), [self.expression(owner, env), *[self.expression(a, env) for a in node.value.args]])
                        result.evidence.add(self.cite(node, "assignment"))
                        env[owner.id] = result
            elif isinstance(node, ast.For):
                iterable = self.expression(node.iter, env)
                if iterable.known and isinstance(iterable.value, (tuple, list, dict)) and len(iterable.value) <= 30:
                    for item in iterable.value:
                        local = copy.deepcopy(env)
                        member = copy.deepcopy(iterable)
                        member.value = item
                        member.evidence.add(self.cite(node.iter, "loop_values"))
                        self.bind(node.target, member, local)
                        self.statements(node.body, local, conditions)
                        # Preserve dependent accumulators after literal expansion.
                        for key, value in local.items():
                            if value.diagnostics or value.excluded_dependencies:
                                env[key] = value
                else:
                    local = copy.deepcopy(env)
                    member = copy.deepcopy(iterable)
                    member.known = False
                    self.bind(node.target, member, local)
                    self.statements(node.body, local, conditions)
                self.statements(node.orelse, env, conditions)
            elif isinstance(node, ast.If):
                predicate, value = self.predicate(node.test, env)
                value.evidence.add(self.cite(node.test, "predicate"))
                yes = (*conditions, (predicate, value))
                no = (*conditions, (f"not ({predicate})", value))
                if value.known and type(value.value) is bool:
                    self.statements(node.body if value.value else node.orelse, env, yes if value.value else no)
                    continue
                body_alert = self.contains_alert(node.body)
                else_alert = self.contains_alert(node.orelse)
                if (body_alert or else_alert) and not value.excluded_dependencies:
                    self.required_variables.update(value.variables)
                if (body_alert or else_alert) and (value.diagnostics or value.excluded_dependencies):
                    # Only the leaf alternatives directly paired with alert
                    # logging get a no-alert rule. Eligibility guards stay in
                    # the path and do not become healthy on their false branch.
                    nested_body = any(isinstance(n, ast.If) and self.contains_alert([n]) for n in node.body)
                    nested_else = any(isinstance(n, ast.If) and self.contains_alert([n]) for n in node.orelse)
                    if body_alert and not nested_body:
                        self.add_rule(node, yes, "MANUAL_REVIEW_REQUIRED", env)
                    if else_alert and not nested_else:
                        self.add_rule(node, no, "MANUAL_REVIEW_REQUIRED", env)
                    if not body_alert and else_alert:
                        self.add_rule(node, yes, "SOURCE_NO_ALERT", env)
                    if body_alert and not else_alert and not nested_body:
                        self.add_rule(node, no, "SOURCE_NO_ALERT", env)
                yes_env, no_env = copy.deepcopy(env), copy.deepcopy(env)
                pending_before = copy.deepcopy(self.pending_queries)
                self.statements(node.body, yes_env, yes)
                pending_yes = copy.deepcopy(self.pending_queries)
                self.pending_queries = copy.deepcopy(pending_before)
                self.statements(node.orelse, no_env, no)
                pending_no = copy.deepcopy(self.pending_queries)
                self.pending_queries = {}
                for key in set(pending_yes) | set(pending_no):
                    left, right = pending_yes.get(key), pending_no.get(key)
                    if left and right and left.diagnostics == right.diagnostics:
                        self.pending_queries[key] = left
                    elif left or right:
                        self.unknown(node, "A query cursor has branch-dependent results. Its selected result and classification require explicit review.")
                for key in set(yes_env) | set(no_env):
                    left, right = yes_env.get(key), no_env.get(key)
                    if left and right and left.known and right.known and left.value == right.value:
                        env[key] = left
                    else:
                        env[key] = self.merged(key, [v for v in (left, right) if v])
                        if left and right and left.diagnostics != right.diagnostics:
                            env[key].unknown_inputs.add(f"branch-dependent value {key}")
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = self.expression(item.context_expr, env)
                    if item.optional_vars:
                        self.bind(item.optional_vars, value, env)
                self.statements(node.body, env, conditions)
            elif isinstance(node, ast.Try):
                self.statements(node.body, env, conditions)
                # Exception/finally handlers are not successful diagnostic paths.
                self.statements(node.orelse, env, conditions)
            elif isinstance(node, ast.Return) and node.value:
                self.expression(node.value, env)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        env.pop(target.id, None)
                    else:
                        self.invalidate_container(target, Value(ast.unparse(target)), env)
            elif isinstance(node, ast.While):
                self.unknown(node, "An unbounded runtime loop requires administrator review; it is not expanded.")

    def build(self, validate: bool = True) -> dict:
        self.statements(self.tree.body, {})
        facts = analyze_dag_source(self.source)
        questions = []
        for key, variable in self.variables.items():
            variable["required"] = key in self.required_variables
            if variable["required"] and not variable["confirmed"]:
                questions.append({"kind": "airflow_variable", "key": key,
                    "prompt": f"What is the deployed value of Airflow Variable '{key}'? Enter JSON; do not enter credentials.",
                    "evidence_ids": variable["evidence_ids"]})
        self.connections = {key: connection for key, connection in self.connections.items()
                            if key in self.required_connections}
        for key, connection in self.connections.items():
            source_type = connection.get("type", "UNKNOWN")
            if source_type not in {"UNKNOWN", self.target["type"]}:
                connection["confirmed"] = False
                evidence_id = connection["evidence_ids"][0]
                item = {
                    "reason": f"Source connection '{key}' requires a {source_type} target, but this draft selects one {self.target['type']} target. This source-mode workflow cannot bind multiple target types; use a reviewed multi-target SOP rather than mapping different connections to the same selected target.",
                    "evidence_ids": [evidence_id], "code": "INCOMPATIBLE_TARGET",
                }
                if item not in self.unknowns:
                    self.unknowns.append(item)
                continue
            mapping = self.mappings.get(key, {})
            connection["suggested_mapping"] = {
                "hostname": self.target.get("hostname", ""),
                "port": self.target.get("port"),
                "database_name": self.target.get("database_name", "") if self.target["type"] == "DATABASE" else "",
                "confirmed": False,
            }
            valid = (mapping.get("confirmed") is True and mapping.get("hostname", "").strip().casefold() == self.target.get("hostname", "").strip().casefold()
                     and mapping.get("port") == self.target.get("port")
                     and (self.target["type"] != "DATABASE" or mapping.get("database_name", "") == self.target.get("database_name", "")))
            connection["confirmed"] = bool(valid and self.target.get("hostname"))
            if connection["confirmed"]:
                connection["mapping"] = mapping
            else:
                questions.append({"kind": "connection_mapping", "key": key,
                    "prompt": f"Confirm that deployed Airflow connection '{key}' identifies the selected RCA target shown below. Its saved host, port and database (if applicable) are prefilled; target selection alone does not verify the Airflow mapping.",
                    "evidence_ids": connection["evidence_ids"]})
        if not self.diagnostics:
            self.unknown(self.tree.body[0], "No exact, approved read-only diagnostic could be resolved from the executed source.")
        if self.diagnostics and not self.rules:
            self.unknown(self.tree.body[0], "No complete diagnostic-to-alert branch was traced. Imported helper behavior or disabled alert logic must be reviewed explicitly.", "NO_ALERT_COVERAGE")
        rule_evidence = {ref for rule in self.rules for ref in rule["evidence_ids"]}
        self.thresholds = [item for item in self.thresholds if rule_evidence.intersection(item["evidence_ids"])]
        for diagnostic in self.diagnostics:
            expected = "query_database" if self.target["type"] == "DATABASE" else "run_ssh_command"
            if diagnostic["tool"] != expected:
                self.unknown(self.tree.body[0], "The source needs a different target type or multiple targets; this draft cannot bind every diagnostic to one selected target.")
            if diagnostic.get("excluded_dependency_ids"):
                self.unknown(self.tree.body[0], f"{diagnostic['id']} has unresolved execution eligibility depending on excluded output; it cannot be activated by a coverage acknowledgement.")
            if not diagnostic["connection_ids"]:
                self.unknown(self.tree.body[0], f"{diagnostic['id']} has no resolved source connection; its target binding requires review.")
            # A read-only source check can supply supporting detail without
            # controlling an alert branch. Missing alert coverage is reported
            # by add_rule / NO_ALERT_COVERAGE above; an unused observation is
            # not itself evidence that the traced branch is incomplete.
        for unknown in self.unknowns:
            identity = json.dumps(unknown, sort_keys=True, separators=(",", ":"))
            unknown["id"] = "warning_" + hashlib.sha256(identity.encode()).hexdigest()[:24]
            unknown["acknowledgeable"] = unknown["code"] in COVERAGE_WARNING_CODES
        plan = {
            "schema_version": 1, "source_sha256": hashlib.sha256(self.source.encode()).hexdigest(),
            "target": self.target, "evidence": list(self.evidence.values()),
            "diagnostics": self.diagnostics, "rules": self.rules,
            "thresholds": self.thresholds,
            "airflow_variables": [item for item in self.variables.values() if item["required"]],
            "ignored_airflow_variables": [item for item in self.variables.values() if not item["required"]],
            "connections": list(self.connections.values()), "unknowns": self.unknowns,
            "external_script_policy": self.external_script_policy,
            "external_operations": self.external_operations,
            "confirmation_questions": questions,
        }
        plan["coverage_review"] = coverage_review(plan, None)
        plan["onboarding_review"] = onboarding_review(plan)
        if validate:
            validate_plan(plan, self.source)
        return plan


def build_plan(source: str, target: dict, variable_values: dict | None = None, mappings: dict | None = None,
               external_script_policy: str = "EXCLUDE", limited_coverage_acknowledgement: dict | None = None) -> dict:
    if not source.strip():
        raise ValueError("Paste the complete DAG source.")
    plan = PlanBuilder(source, target, variable_values or {}, mappings or {}, external_script_policy).build()
    plan["coverage_review"] = coverage_review(plan, limited_coverage_acknowledgement)
    plan["onboarding_review"] = onboarding_review(plan)
    return plan


def target_from_registration(registration: dict, context: dict) -> dict:
    database = registration["mode"] in {"EXISTING_DATABASE", "NEW_DATABASE"}
    metadata = registration.get("target", registration)
    key = "database_target_id" if database else "target_id"
    target_id = metadata[key]
    if registration["mode"].startswith("EXISTING"):
        collection = context["database_targets" if database else "ssh_targets"]
        metadata = next((item for item in collection if item[key] == target_id), {})
    return {"id": target_id, "type": "DATABASE" if database else "SSH",
            "hostname": metadata.get("hostname", ""),
            "port": metadata.get("database_port" if database else "ssh_port", 3306 if database else 22),
            "database_name": metadata.get("database_name", "") if database else ""}


COVERAGE_WARNING_CODES = frozenset({
    "EXCLUDED_OUTPUT_COVERAGE", "UNTRACED_ALERT_COVERAGE",
    "NO_ALERT_COVERAGE", "CHECK_WITHOUT_RULE", "UNRESOLVED_RULE_COVERAGE",
})
LIMITED_COVERAGE_MARKER = "RCA_LIMITED_COVERAGE_V1"


def coverage_review(plan: dict, acknowledgement: dict | None) -> dict:
    warnings = [item for item in plan["unknowns"] if item.get("code") in COVERAGE_WARNING_CODES]
    eligible = bool(warnings and plan["diagnostics"] and not plan["confirmation_questions"]
                    and all(item.get("code") in COVERAGE_WARNING_CODES for item in plan["unknowns"]))
    # Bind to the canonical plan: source, diagnostic operations, rules, selected
    # target identity, confirmed inputs, exclusions and exact warning inventory.
    basis = {key: value for key, value in plan.items() if key not in {"coverage_review", "onboarding_review"}}
    token = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    review = {"eligible": eligible, "token": token if eligible else "",
              "warning_ids": [item["id"] for item in warnings],
              "accepted": False, "reason": "", "final_classification": "INCONCLUSIVE"}
    if acknowledgement is not None:
        if not isinstance(acknowledgement, dict) or set(acknowledgement) != {"acknowledged", "review_token", "reason"}:
            raise ValueError("Invalid limited-coverage acknowledgement.")
        reason = acknowledgement.get("reason")
        if not eligible or acknowledgement.get("acknowledged") is not True:
            raise ValueError("Only diagnostic coverage warnings can be accepted; resolve all required inputs, target mappings and policy blockers first.")
        if acknowledgement.get("review_token") != token:
            raise ValueError("The limited-coverage review changed. Regenerate and acknowledge the current draft.")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 1000:
            raise ValueError("Record a reason of 1 to 1000 characters for accepting limited diagnostic coverage.")
        review.update(accepted=True, reason=reason.strip())
    return review


def blocking_unknowns(plan: dict) -> list[dict]:
    accepted = set(plan.get("coverage_review", {}).get("warning_ids", [])) if plan.get("coverage_review", {}).get("accepted") else set()
    return [item for item in plan["unknowns"] if item.get("code") not in COVERAGE_WARNING_CODES or item.get("id") not in accepted]


def onboarding_review(plan: dict) -> dict:
    """Present readiness and coverage separately; never use prose as authority."""
    hard = [item for item in plan["unknowns"] if item.get("code") not in COVERAGE_WARNING_CODES]
    warnings = [item for item in plan["unknowns"] if item.get("code") in COVERAGE_WARNING_CODES]
    questions = plan["confirmation_questions"]
    ready = bool(plan["diagnostics"]) and not hard and not questions
    accepted = plan["coverage_review"]["accepted"]
    if hard:
        status, title = "NEEDS_REVIEW", "Some diagnostics need review"
    elif questions:
        status, title = "NEEDS_INPUT", "Confirm the remaining configuration"
    elif warnings:
        status, title = "READY_WITH_WARNINGS", "Ready with limited diagnostic coverage"
    else:
        status, title = "READY", "Ready for review"
    checks = []
    for diagnostic in plan["diagnostics"]:
        covered = any(diagnostic["id"] in rule["diagnostic_ids"] for rule in plan["rules"])
        label = "Read database results" if diagnostic["tool"] == "query_database" else "Run the source's read-only SSH check"
        if diagnostic["tool"] == "query_database":
            table = re.search(r"\bFROM\s+(`?[A-Za-z_][\w]*`?(?:\.`?[A-Za-z_][\w]*`?)?)", diagnostic["operation"], re.IGNORECASE)
            if table:
                label += " from " + table.group(1).replace("`", "")
        checks.append({"id": diagnostic["id"], "description": label,
                       "target_id": diagnostic["target_id"], "operation": diagnostic["operation"],
                       "role": "Traced to a source rule" if covered else "Observation only"})
    count = len(checks)
    summary = f"{count} approved read-only check{'s' if count != 1 else ''} available."
    if warnings:
        summary += " These checks provide partial evidence; they cannot fully classify the original alert. You may accept this limited scope after resolving the required configuration."
    else:
        summary += " No classification coverage gaps were identified by the supported source analysis."
    supporting = sum(check["role"] == "Observation only" for check in checks)
    if supporting:
        summary += f" {supporting} supporting check{' is' if supporting == 1 else 's are'} optional and does not determine the alert branch."
    excluded = sum(item["status"] == "EXCLUDED" for item in plan["external_operations"])
    if excluded:
        summary += f" {excluded} external Python operation{'s are' if excluded != 1 else ' is'} excluded; their implementation is not required for this scope."
    return {"status": status, "title": title, "summary": summary,
            "can_review": ready, "can_activate": ready and (not warnings or accepted),
            "diagnostic_coverage": "LIMITED" if warnings else "NO_GAPS_IDENTIFIED",
            "coverage_warning_count": len(warnings), "coverage_accepted": accepted,
            "blocking_issues": [{"id": item["id"], "reason": item["reason"]} for item in hard],
            "configuration_count": len(questions), "checks": checks,
            "available_source_rule_count": len(plan["rules"])}


SOURCE_SOP_MARKER = "- Procedure basis: validated DAG source."


def is_source_sop(sop: str) -> bool:
    """Recognize current and legacy generated procedures for activation checks."""
    return SOURCE_SOP_MARKER in sop or "- Source SHA-256:" in sop


def validate_source_activation(source_review: dict | None, draft: dict, context: dict) -> dict | None:
    """Rebuild the reviewed procedure before persistence, without an LLM call."""
    sop = draft["dag"]["investigation_sop"].strip()
    if source_review is None:
        if is_source_sop(sop):
            raise ValueError("A source-backed SOP requires its source review and confirmations.")
        return None
    if not source_review.get("dag_source_code", "").strip() or not source_review.get("investigation_read_only"):
        raise ValueError("The source review must include the complete DAG and read-only confirmation.")
    if draft["operating_mode"] != "INVESTIGATE_ONLY" or source_review["target_registration"] != draft["target_registration"]:
        raise ValueError("The activated mode and target must match the source review.")
    source = source_review["dag_source_code"]
    facts = analyze_dag_source(source)
    dag_id = source_review.get("dag_id") or (facts.dag_ids[0] if len(facts.dag_ids) == 1 else "")
    if len(facts.dag_ids) > 1 or dag_id != draft["dag"]["dag_id"] or (facts.dag_ids and dag_id not in facts.dag_ids):
        raise ValueError("The activated DAG does not match the reviewed source.")
    exceptions = source_review.get("exception_types") or facts.exception_types
    if exceptions != draft["dag"]["exception_types"]:
        raise ValueError("The activated exception types do not match the reviewed source.")
    if source_review.get("investigation_logic", "").strip():
        raise ValueError("Source mode cannot override source operations or rules with free text.")
    plan = build_plan(source, target_from_registration(draft["target_registration"], context),
                      source_review.get("airflow_variable_values", {}), source_review.get("connection_mappings", {}),
                      source_review.get("external_script_policy", "EXCLUDE"),
                      source_review.get("limited_coverage_acknowledgement"))
    if plan["confirmation_questions"] or blocking_unknowns(plan):
        raise ValueError("Resolve every source input, connection mapping and unsupported diagnostic path before activation.")
    if sop != render_sop(plan, dag_id):
        raise ValueError("The edited SOP differs from the source-backed procedure. Regenerate it from the reviewed source inputs.")
    return plan


def validate_plan(plan: dict, source: str) -> None:
    """Validate provenance, identifiers and policy before SOP rendering."""
    if plan["source_sha256"] != hashlib.sha256(source.encode()).hexdigest():
        raise ValueError("The diagnostic plan belongs to different source code.")
    tree = ast.parse(source)
    segments = {(n.lineno, getattr(n, "end_lineno", n.lineno), ast.get_source_segment(source, n) or ast.unparse(n))
                for n in ast.walk(tree) if hasattr(n, "lineno")}
    ids = set()
    for evidence in plan["evidence"]:
        if evidence["id"] in ids or (evidence["start_line"], evidence["end_line"], evidence["source"]) not in segments:
            raise ValueError("Source evidence is duplicated or does not match the pasted DAG.")
        ids.add(evidence["id"])
    checks = {item["id"] for item in plan["diagnostics"]}
    if len(checks) != len(plan["diagnostics"]):
        raise ValueError("Duplicate diagnostic identifiers.")
    for collection in ("diagnostics", "rules", "thresholds", "airflow_variables", "ignored_airflow_variables", "connections", "unknowns", "external_operations"):
        for item in plan[collection]:
            if not item["evidence_ids"] or not set(item["evidence_ids"]).issubset(ids):
                raise ValueError("Every plan item must reference valid source evidence.")
    for diagnostic in plan["diagnostics"]:
        approved = is_read_only_select(diagnostic["operation"]) if diagnostic["tool"] == "query_database" else is_read_only_ssh_command(diagnostic["operation"])
        if not approved or diagnostic["target_id"] != plan["target"]["id"]:
            raise ValueError("A diagnostic is outside the read-only target policy.")
    for rule in plan["rules"]:
        if not rule["diagnostic_ids"] or not set(rule["diagnostic_ids"]).issubset(checks) or rule["outcome"] not in {"SOURCE_NO_ALERT", "MANUAL_REVIEW_REQUIRED"}:
            raise ValueError("A rule has an invalid diagnostic reference or outcome.")
    # Rebuild the canonical source derivation. Citations alone do not prove
    # that a changed predicate or safe-but-unrelated command came from source.
    supplied = {item["name"]: json.dumps(item["value"]) for item in [*plan["airflow_variables"], *plan["ignored_airflow_variables"]] if item["confirmed"]}
    mappings = {item["id"]: item["mapping"] for item in plan["connections"] if item["confirmed"]}
    canonical = PlanBuilder(source, plan["target"], supplied, mappings, plan.get("external_script_policy", "EXCLUDE")).build(validate=False)
    for key in ("diagnostics", "rules", "thresholds", "unknowns", "external_operations", "connections", "confirmation_questions"):
        if canonical[key] != plan[key]:
            raise ValueError(f"The {key} differ from the canonical source derivation.")
    review = plan.get("coverage_review", {})
    acknowledgement = ({"acknowledged": True, "review_token": review.get("token"), "reason": review.get("reason")}
                       if review.get("accepted") else None)
    if coverage_review(canonical, acknowledgement) != review:
        raise ValueError("The coverage review differs from the canonical source derivation.")
    if onboarding_review({**canonical, "coverage_review": review}) != plan.get("onboarding_review"):
        raise ValueError("The onboarding summary differs from the canonical source derivation.")


def explanation_notes(payload: Any, plan: dict) -> list[dict]:
    """Accept cited non-operative notes only; never merge LLM plan fields."""
    if not isinstance(payload, dict) or set(payload) != {"notes"} or not isinstance(payload["notes"], list):
        raise ValueError("The explanation response must contain only notes.")
    evidence_ids = {item["id"] for item in plan["evidence"]}
    accepted = []
    for item in payload["notes"][:20]:
        if not isinstance(item, dict) or set(item) != {"evidence_ids", "explanation"}:
            raise ValueError("Explanation notes cannot contain operations or rules.")
        refs, explanation = item["evidence_ids"], item["explanation"]
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref in evidence_ids for ref in refs):
            raise ValueError("An explanation has no valid source citations.")
        if not isinstance(explanation, str) or not 1 <= len(explanation) <= 1500:
            raise ValueError("An explanation is empty or too long.")
        accepted.append(item)
    return accepted


def _source_calculations_for_rules(plan: dict) -> list[str]:
    """Keep only assignment chains needed to interpret a traced predicate."""
    used = {ref for rule in plan["rules"] for ref in rule["evidence_ids"]}
    external = {ref for item in plan.get("external_operations", []) for ref in item["evidence_ids"]}
    needed = set()
    for rule in plan["rules"]:
        try:
            tree = ast.parse(rule["condition"], mode="eval")
        except SyntaxError:
            continue
        needed.update(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))

    candidates = []
    for evidence in plan["evidence"]:
        if evidence["id"] not in used or evidence["id"] in external or evidence["kind"] != "assignment":
            continue
        expression = evidence["source"]
        try:
            statements = ast.parse(textwrap.dedent(expression)).body
        except SyntaxError:
            continue
        if len(statements) != 1 or not isinstance(statements[0], (ast.Assign, ast.AnnAssign)):
            continue
        statement = statements[0]
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        defined = {node.id for target in targets for node in ast.walk(target) if isinstance(node, ast.Name)}
        referenced = {node.id for node in ast.walk(statement.value) if isinstance(node, ast.Name)}
        candidates.append((expression, defined, referenced))

    chosen = []
    # A source snippet can be cited more than once through a bounded loop.
    for expression, defined, referenced in reversed(candidates):
        if not defined.intersection(needed):
            continue
        if defined.issubset({"client", "conn", "connection", "cursor", "hook", "stdin", "stdout", "stderr"}):
            continue
        if expression not in chosen:
            chosen.append(expression)
        needed.update(referenced)
    return list(reversed(chosen))


def _count_check(check: dict) -> bool:
    """The command's result is an integer count; no DAG or script name is used."""
    if check["tool"] != "run_ssh_command":
        return False
    try:
        parts = shlex.split(check["operation"])
    except ValueError:
        return False
    return bool(parts and parts[0].rsplit("/", 1)[-1] == "pgrep" and any(
        part == "--count" or (part.startswith("-") and not part.startswith("--") and "c" in part[1:])
        for part in parts[1:]
    ))


def _calculation_plan(plan: dict) -> tuple[dict[str, str], list[str]]:
    """Translate the traced assignment chain into measurement instructions.

    Transport and parsing assignments are represented by the check's output
    contract. Unrecognized calculations are kept as source expressions with
    transport names expanded, so the renderer cannot silently drop a formula.
    """
    aliases: dict[str, str] = {}
    calculations: list[str] = []
    rule_checks = {check_id for rule in plan["rules"] for check_id in rule["diagnostic_ids"]}
    all_counts = bool(rule_checks) and all(
        _count_check(c) for c in plan["diagnostics"] if c["id"] in rule_checks
    )
    for expression in _source_calculations_for_rules(plan):
        try:
            statement = ast.parse(textwrap.dedent(expression)).body[0]
        except (SyntaxError, IndexError):
            continue
        target = statement.targets[0] if isinstance(statement, ast.Assign) else statement.target
        value = statement.value
        if isinstance(value, ast.Call) and (
            call_name(value.func) in {"init_db_proj", "init_db_airflow", "SSHHook", "get_conn", "cursor"}
        ):
            # These assignments choose a transport; the diagnostic already
            # records its approved target and exact operation.
            continue
        if (isinstance(target, (ast.Tuple, ast.List))
                and isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "fetchone"):
            names = [part.id for part in target.elts if isinstance(part, ast.Name)]
            if len(names) == len(target.elts):
                for column, name in enumerate(names, 1):
                    aliases[name] = f"result column {column}"
                calculations.append(
                    f"Read columns 1–{len(names)} from the database result row in source order."
                )
                continue
        if not isinstance(target, ast.Name):
            continue
        name = target.id
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and isinstance(value.func.value, ast.Name)):
            owner, method = value.func.value.id, value.func.attr
            if owner == "stdout" and method in {"read", "readlines"}:
                aliases[name] = "SSH output"
                continue
            if owner == "cursor" and method in {"fetchone", "fetchall"}:
                aliases[name] = "database result" + (" row" if method == "fetchone" else " rows")
                continue
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id in {"int", "float"} and len(value.args) == 1
                and any(isinstance(part, ast.Name) and aliases.get(part.id) == "SSH output"
                        for part in ast.walk(value.args[0]))):
            aliases[name] = "process count" if all_counts else "numeric SSH result"
            continue
        if (isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name)
                and aliases.get(value.value.id) == "database result row"):
            column = (value.slice.value + 1 if isinstance(value.slice, ast.Constant)
                      and type(value.slice.value) is int and value.slice.value >= 0 else None)
            aliases[name] = (f"column {column} value" if name.lower() in {"vout", "vstdout", "output"} and column is not None
                             else name.replace("_", " "))
            if column is not None:
                calculations.append(f"Read {aliases[name]} from column {column} of the database result row.")
            else:
                calculations.append(f"Read {aliases[name]} from the database result row as specified by the source.")
            continue
        if (isinstance(value, ast.Subscript) and isinstance(value.value, ast.Call)
                and isinstance(value.value.func, ast.Attribute)
                and isinstance(value.value.func.value, ast.Name)
                and value.value.func.value.id == "cursor"
                and value.value.func.attr == "fetchone"
                and isinstance(value.slice, ast.Constant) and type(value.slice.value) is int
                and value.slice.value >= 0):
            column = value.slice.value + 1
            aliases[name] = (f"column {column} value" if name.lower() in {"vout", "vstdout", "output"}
                             else name.replace("_", " "))
            calculations.append(f"Read {aliases[name]} from column {column} of the database result row.")
            continue
        aliases[name] = name.replace("_", " ")
        calculations.append(f"Calculate {aliases[name]} from {_readable_expression(value, aliases)}.")
    return aliases, list(dict.fromkeys(calculations))


def _readable_expression(node: ast.AST, aliases: dict[str, str]) -> str:
    """Render a source expression as text without executing it."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id.replace("_", " "))
    if isinstance(node, ast.Constant):
        return repr(node.value) if isinstance(node.value, str) else str(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        if isinstance(node.operand, ast.Compare) and len(node.operand.ops) == 1:
            inverted = {ast.Eq: "≠", ast.NotEq: "=", ast.Gt: "≤", ast.GtE: "<", ast.Lt: "≥", ast.LtE: ">"}
            op = inverted.get(type(node.operand.ops[0]))
            if op:
                return f"{_readable_expression(node.operand.left, aliases)} {op} {_readable_expression(node.operand.comparators[0], aliases)}"
        return f"not ({_readable_expression(node.operand, aliases)})"
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        ops = {ast.Eq: "=", ast.NotEq: "≠", ast.Gt: ">", ast.GtE: "≥", ast.Lt: "<", ast.LtE: "≤"}
        symbol = ops.get(type(node.ops[0]))
        if symbol:
            return f"{_readable_expression(node.left, aliases)} {symbol} {_readable_expression(node.comparators[0], aliases)}"
    if isinstance(node, ast.BoolOp):
        conjunction = " and " if isinstance(node.op, ast.And) else " or "
        return conjunction.join(
            "(" + _readable_expression(part, aliases) + ")"
            if isinstance(part, ast.BoolOp) and type(part.op) is not type(node.op)
            else _readable_expression(part, aliases)
            for part in node.values
        )
    if isinstance(node, ast.Subscript):
        base = _readable_expression(node.value, aliases)
        if isinstance(node.slice, ast.Slice):
            start = node.slice.lower.value if isinstance(node.slice.lower, ast.Constant) else None
            stop = node.slice.upper.value if isinstance(node.slice.upper, ast.Constant) else None
            if start in (0, None) and type(stop) is int and stop >= 0:
                return (f"the first {stop} {base}" if base.endswith(" rows")
                        else f"the first {stop} rows of {base}")
        if isinstance(node.slice, ast.Constant) and type(node.slice.value) is int and node.slice.value >= 0:
            return f"column {node.slice.value + 1} of {base}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and len(node.args) == 1:
        if node.func.id == "len":
            return "the number of " + _readable_expression(node.args[0], aliases)
        if node.func.id == "sum" and isinstance(node.args[0], (ast.GeneratorExp, ast.ListComp)):
            part = node.args[0]
            if len(part.generators) == 1:
                item, generator = part.elt, part.generators[0]
                if (isinstance(item, ast.Subscript) and isinstance(item.value, ast.Name)
                        and isinstance(generator.target, ast.Name) and item.value.id == generator.target.id):
                    if isinstance(item.slice, ast.Constant) and type(item.slice.value) is int and item.slice.value >= 0:
                        return (f"the sum of column {item.slice.value + 1} from each row in "
                                + _readable_expression(generator.iter, aliases))
    if isinstance(node, ast.BinOp):
        ops = {ast.Add: "+", ast.Sub: "−", ast.Mult: "×", ast.Div: "/", ast.FloorDiv: "//"}
        op = ops.get(type(node.op))
        if op:
            return f"({_readable_expression(node.left, aliases)} {op} {_readable_expression(node.right, aliases)})"
    # Retain an unsupported source calculation visibly. Substitute known
    # transport aliases; never imply that a translation was lossless.
    class ReplaceKnown(ast.NodeTransformer):
        def visit_Name(self, name):
            label = aliases.get(name.id)
            return ast.copy_location(ast.Name(id=label.replace(" ", "_"), ctx=name.ctx), name) if label else name
    return ast.unparse(ReplaceKnown().visit(copy.deepcopy(node))).replace("_", " ")


def _numeric_branch_groups(plan: dict, aliases: dict[str, str]) -> list[dict] | None:
    """Fold single-measure numeric branches into disjoint, exact intervals.

    Only basic numeric comparisons are supported. Every interval is checked
    against every traced rule, so conflicts and missing coverage stay visible.
    """
    rules = plan["rules"]
    rule_checks = {check_id for rule in rules for check_id in rule["diagnostic_ids"]}
    checks = [check for check in plan["diagnostics"] if check["id"] in rule_checks]
    if not rules or not checks or any(len(rule["diagnostic_ids"]) != 1 for rule in rules):
        return None
    predicates: dict[str, ast.AST] = {}
    names: set[str] = set()
    bounds: set[int | float] = set()
    operators = {ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE}
    def permitted(node: ast.AST) -> bool:
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            return all(permitted(part) for part in node.values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return permitted(node.operand)
        if (isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in operators
                and isinstance(node.left, ast.Name) and isinstance(node.comparators[0], ast.Constant)
                and type(node.comparators[0].value) in (int, float)):
            names.add(node.left.id)
            bounds.add(node.comparators[0].value)
            return True
        return False
    for rule in rules:
        try:
            tree = ast.parse(rule["condition"], mode="eval").body
        except SyntaxError:
            return None
        if not permitted(tree):
            return None
        predicates[rule["id"]] = tree
    if len(names) != 1 or not bounds or any(not math.isfinite(v) for v in bounds):
        return None
    name = next(iter(names))

    def matches(node: ast.AST, x: float) -> bool:
        if isinstance(node, ast.BoolOp):
            values = [matches(part, x) for part in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp):
            return not matches(node.operand, x)
        value = node.comparators[0].value
        op = node.ops[0]
        return (x == value if isinstance(op, ast.Eq) else x != value if isinstance(op, ast.NotEq)
                else x > value if isinstance(op, ast.Gt) else x >= value if isinstance(op, ast.GtE)
                else x < value if isinstance(op, ast.Lt) else x <= value)

    ordered = sorted(bounds)
    # Alternate open intervals and exact thresholds. A count check has the
    # domain of nonnegative integers; a SQL measurement is left unrestricted.
    zones = [(None, ordered[0], False, False, ordered[0] - 1)]
    for index, bound in enumerate(ordered):
        zones.append((bound, bound, True, True, bound))
        right = ordered[index + 1] if index + 1 < len(ordered) else None
        zones.append((bound, right, False, False, (bound + right) / 2 if right is not None else bound + 1))
    by_check: dict[str, tuple] = {}
    for check in checks:
        count = _count_check(check)
        observations = []
        for lower, upper, include_lower, include_upper, sample in zones:
            if count:
                # Intersect with the command's nonnegative-integer domain.
                first = max(0, (math.ceil(lower) if include_lower else math.floor(lower) + 1)
                            if lower is not None else 0)
                last = ((math.floor(upper) if include_upper else math.ceil(upper) - 1)
                        if upper is not None else None)
                if last is not None and first > last:
                    continue
                lower, upper, include_lower, include_upper, sample = first, last, True, True, first
            outcomes = {rule["outcome"] for rule in rules if check["id"] in rule["diagnostic_ids"]
                        and matches(predicates[rule["id"]], sample)}
            if len(outcomes) > 1:
                return None
            observations.append((lower, upper, include_lower, include_upper,
                                 next(iter(outcomes)) if outcomes else None))
        # Preserve the interval boundaries; coalesce adjacent pieces with the
        # same outcome, including gaps that no source branch assesses.
        merged = []
        for lower, upper, include_lower, include_upper, outcome in observations:
            adjacent = (merged and (not count or merged[-1][1] is not None
                                    and merged[-1][1] + 1 == lower))
            if adjacent and merged[-1][4] == outcome:
                merged[-1] = (merged[-1][0], upper, merged[-1][2], include_upper, outcome)
            else:
                merged.append((lower, upper, include_lower, include_upper, outcome))
        by_check[check["id"]] = tuple(merged)
    groups: dict[tuple, list[str]] = {}
    for check_id, intervals in by_check.items():
        groups.setdefault(intervals, []).append(check_id)
    result = []
    for intervals, ids in groups.items():
        branches = []
        group_count = all(_count_check(check) for check in checks if check["id"] in ids)
        label_name = aliases.get(name, name.replace("_", " "))
        if group_count and label_name == "numeric SSH result":
            label_name = "process count"
        for lower, upper, include_lower, include_upper, outcome in intervals:
            if outcome is None:
                continue
            if group_count and lower == upper:
                label = f"{label_name} = {lower:g}"
            elif group_count and lower == 0 and upper is not None:
                label = f"{label_name} ≤ {upper:g}"
            elif group_count and upper is None:
                label = f"{label_name} > {lower - 1:g}" if lower else f"{label_name} ≥ 0"
            elif group_count:
                label = f"{lower:g} ≤ {label_name} ≤ {upper:g}"
            elif lower == upper:
                label = f"{label_name} = {lower:g}"
            elif lower is None:
                label = f"{label_name} {'≤' if include_upper else '<'} {upper:g}"
            elif upper is None:
                label = f"{label_name} {'≥' if include_lower else '>'} {lower:g}"
            else:
                label = (f"{lower:g} {'≤' if include_lower else '<'} {label_name} "
                         f"{'≤' if include_upper else '<'} {upper:g}")
            branches.append((label, outcome))
        result.append({"diagnostic_ids": ids, "intervals": intervals, "name": label_name,
                       "count": group_count, "branches": branches})
    return result


def _interpretation_structure(plan: dict) -> dict:
    """One render model for every source-backed calculation and decision.

    Simple numeric predicates receive exact interval labels; other traced
    predicates remain readable source conditions. Both paths populate the
    same check-bound branch records, without changing the canonical plan.
    """
    aliases, calculations = _calculation_plan(plan)
    structure = {"calculations": calculations, "validations": [], "branches": []}
    numeric_groups = _numeric_branch_groups(plan, aliases)
    if numeric_groups is not None:
        for group in numeric_groups:
            group_checks = [check for check in plan["diagnostics"] if check["id"] in group["diagnostic_ids"]]
            if group["count"]:
                validation = "parse stdout as one nonnegative integer count; an invalid count is INCONCLUSIVE"
            elif all(check["tool"] == "run_ssh_command" for check in group_checks):
                validation = "read one numeric SSH result; missing or invalid output is INCONCLUSIVE"
            else:
                validation = (f"use a present, numeric {group['name']} value; "
                              "NULL or an invalid value is INCONCLUSIVE")
            structure["validations"].append({
                "diagnostic_ids": group["diagnostic_ids"],
                "text": validation,
            })
            structure["branches"].extend({
                "diagnostic_ids": group["diagnostic_ids"], "condition": condition,
                "outcome": outcome,
            } for condition, outcome in group["branches"])
        assessed = {check_id for group in numeric_groups for check_id in group["diagnostic_ids"]}
        for check in plan["diagnostics"]:
            if check["id"] not in assessed:
                structure["validations"].append({
                    "diagnostic_ids": [check["id"]],
                    "text": "record the output as an observation; no classification rule was traced to this check",
                })
    else:
        grouped: dict[tuple[str, str], list[str]] = {}
        for rule in plan["rules"]:
            try:
                condition = _readable_expression(ast.parse(rule["condition"], mode="eval").body, aliases)
            except SyntaxError:
                condition = rule["condition"]
            ids = grouped.setdefault((condition, rule["outcome"]), [])
            for check_id in rule["diagnostic_ids"]:
                if check_id not in ids:
                    ids.append(check_id)
        structure["branches"] = [
            {"diagnostic_ids": ids, "condition": condition, "outcome": outcome}
            for (condition, outcome), ids in grouped.items()
        ]
    return structure


def render_sop(plan: dict, dag_id: str) -> str:
    """Render the validated source plan as a concise Verifier-ready procedure.

    The canonical plan retains source citations and configuration confirmations.
    The SOP contains only the operational facts the Verifier needs at runtime.
    It is still regenerated and compared byte-for-byte on activation.
    """
    target = plan["target"]
    target_id = target["id"]
    destination = target.get("hostname", "")
    if destination:
        destination += f":{target.get('port', 22 if target['type'] == 'SSH' else 3306)}"
        if target.get("database_name"):
            destination += f"/{target['database_name']}"

    lines = [f"# INVESTIGATION SOP FOR {dag_id}", "",
             f"Component ID: {dag_id}", "Operating mode: INVESTIGATE_ONLY",
             f"Registered {target['type']} target: {target_id}" +
             (f" ({destination})" if destination else ""), SOURCE_SOP_MARKER]

    # Values confirmed in the onboarding review are SOP assumptions. They do
    # not create extra live checks that the Verifier cannot perform.
    variables = [item for item in plan["airflow_variables"] if item.get("required", True)]
    if variables:
        lines += ["", "Configured values used for this procedure:"]
        for item in variables:
            value = json.dumps(item["value"], ensure_ascii=False) if item["confirmed"] else "UNCONFIRMED"
            lines.append(f"- {item['name']}: {value}")
    if plan["confirmation_questions"]:
        lines += ["", "Draft only: resolve the remaining configuration questions before activation."]

    review = plan.get("coverage_review", {})
    if review.get("accepted"):
        lines += ["", "Limited diagnostic coverage was accepted during onboarding. The"
                  " listed checks can report observations, but cannot fully assess"
                  " the original alert. The overall Verifier classification for this"
                  " procedure must remain INCONCLUSIVE.",
                  f"<!-- {LIMITED_COVERAGE_MARKER}:{review['token']} -->"]

    interpretation = _interpretation_structure(plan)
    lines += ["", "Expected healthy state:"]
    if review.get("accepted") or not plan["rules"]:
        lines.append("The listed checks collect current observations. No complete source-backed healthy branch is available for the original alert.")
    else:
        lines.append("Every required check must return a valid result and satisfy its source non-alert branch below. A normal current result does not explain an earlier alert.")

    rule_checks = {check_id for rule in plan["rules"] for check_id in rule["diagnostic_ids"]}
    lines += ["", "Run the following exact classification checks in order."
              " Supporting observations are optional; they cannot establish a healthy branch.", ""]
    for index, check in enumerate(plan["diagnostics"], 1):
        tool = check["tool"]
        optional = bool(rule_checks) and check["id"] not in rule_checks
        prefix = "Optional supporting observation: " if optional else ""
        if tool == "query_database":
            lines.append(f"{index}. {prefix}Run query_database on target '{check['target_id']}' with this exact read-only query:")
        else:
            lines.append(f"{index}. {prefix}Run run_ssh_command on target '{check['target_id']}' with this exact command:")
        lines += ["", "```sql" if tool == "query_database" else "```sh",
                  check["operation"], "```", ""]

    lines += [f"{len(plan['diagnostics']) + 1}. Interpret the results:",
              "Evaluate each rule separately for each listed check using that check's own output;"
              " a reused source variable does not share a result between checks."]
    if any(check["tool"] == "query_database"
           and re.search(r"\bIF\s*\(\s*TIMESTAMPDIFF\s*\(", check["operation"], re.IGNORECASE)
           for check in plan["diagnostics"]):
        lines.append("For an IF status calculated from a timestamp difference, require the returned"
                     " timestamp and elapsed-age measurements to be present and the age nonnegative."
                     " NULL or future timestamps are INCONCLUSIVE even if the source labels them healthy.")
    if interpretation["calculations"]:
        lines += ["", "Source calculations needed to interpret the results:"]
        lines.extend("- " + calculation for calculation in interpretation["calculations"])
    step_numbers = {check["id"]: index for index, check in enumerate(plan["diagnostics"], 1)}
    for item in interpretation["validations"]:
        names = ("step " if len(item["diagnostic_ids"]) == 1 else "steps ") + ", ".join(
            str(step_numbers[check_id]) for check_id in item["diagnostic_ids"])
        lines.append(f"- For {names}, {item['text']}.")
    for item in interpretation["branches"]:
        names = ("step " if len(item["diagnostic_ids"]) == 1 else "steps ") + ", ".join(
            str(step_numbers[check_id]) for check_id in item["diagnostic_ids"])
        condition = " ".join(item["condition"].split()).replace("`", "\\`")
        if item["outcome"] == "MANUAL_REVIEW_REQUIRED":
            lines.append(f"- For {names}, {condition}: MANUAL_REVIEW_REQUIRED. Report the measurement and affected check.")
        else:
            lines.append(f"- For {names}, {condition}: source non-alert branch. Use NO_REMEDIATION_REQUIRED only when every required check is valid and all non-alert conditions are met.")
    if not plan["rules"]:
        lines.append("- No complete source-backed alert branch was traced. Report the available measurements and classify the overall incident INCONCLUSIVE.")
    if review.get("accepted"):
        lines.append("- Accepted limited coverage takes precedence over the source branches above: classify the overall incident INCONCLUSIVE and recommend no executable action.")
    else:
        lines.append("- If a valid abnormal branch is established, use MANUAL_REVIEW_REQUIRED and report any other incomplete checks separately. Otherwise, if a required check or decision branch is missing, invalid or ambiguous, use INCONCLUSIVE.")

    lines += ["", "If a required tool fails, times out, is BLOCKED, or returns unreadable or truncated output, report that check as unavailable. Never treat a failed command as a count of zero or a missing SQL row as a healthy result."
              if any(check["tool"] == "query_database" for check in plan["diagnostics"])
              else "If a required tool fails, times out, is BLOCKED, or returns unreadable or truncated output, report that check as unavailable. Never treat a failed command as a count of zero."]
    if any(check["tool"] == "run_ssh_command" and re.match(r"^(?:\S*/)?pgrep\s", check["operation"])
           for check in plan["diagnostics"]):
        lines.append("For pgrep count checks, remote exit code 1 with stdout exactly 0 and no execution error is a valid zero count. Other unexpected exit codes, negative or nonnumeric stdout are INCONCLUSIVE for that check.")
    if plan.get("external_operations"):
        lines.append("External Python script behavior is outside these checks; do not infer its current output or health.")
    if plan["unknowns"]:
        lines += ["", "Review limitations:"]
        lines.extend(f"- {item['reason']}" for item in plan["unknowns"])

    lines += ["", "Do not run writes, process termination, restarts, DAG triggers, deployments, threshold changes, notifications or any other state-changing operation. Only the exact diagnostic checks above are authorized. No automatic remediation is registered by this SOP."]
    return "\n".join(lines)
