"""Static evidence extraction from an administrator-pasted Airflow DAG.

This module parses Python syntax; it never imports or executes DAG code.
The extracted facts are evidence for a draft, not authorization to run a query.
"""

from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass

try:
    from .source_command_analysis import analyze_ssh_source
except ImportError:  # Support isolated analysis tests outside the app package.
    from source_command_analysis import analyze_ssh_source


_SELECT = re.compile(r"^SELECT\b", re.IGNORECASE)
_WRITE_SQL = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|TRUNCATE|"
    r"GRANT|REVOKE|CALL|LOAD)\b",
    re.IGNORECASE,
)
_DANGEROUS_SELECT = re.compile(
    r"\b(?:INTO\s+(?:OUTFILE|DUMPFILE)|FOR\s+UPDATE|LOAD_FILE)\b",
    re.IGNORECASE,
)
_QUERY_ARGUMENTS = {"sql", "query", "statement"}
_TABLE_REFERENCE = re.compile(
    r"\b(?:FROM|JOIN)\s+(`?[A-Za-z_][A-Za-z_0-9]*`?(?:\.`?[A-Za-z_][A-Za-z_0-9]*`?)?)",
    re.IGNORECASE,
)


def _literal_string(node: ast.AST, bindings: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left, bindings)
        right = _literal_string(node.right, bindings)
        if left is not None and right is not None:
            return left + right
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def is_read_only_select(query: str) -> bool:
    statement = query.strip().removesuffix(";").strip()
    return bool(
        _SELECT.match(statement)
        and ";" not in statement
        and not _WRITE_SQL.search(statement)
        and not _DANGEROUS_SELECT.search(statement)
    )


def select_tables(query: str) -> set[str]:
    """Return literal source table names; never resolve dynamic identifiers."""
    return {
        match.group(1).replace("`", "").casefold()
        for match in _TABLE_REFERENCE.finditer(query)
        if match.group(1) != "__DYNAMIC_VALUE__"
    }


def is_source_scoped_diagnostic(query: str, source_tables: list[str]) -> bool:
    """Check that proposed SQL is a read-only SELECT of source-proven tables."""
    tables = select_tables(query)
    return bool(
        is_read_only_select(query)
        and tables
        and tables.issubset(set(source_tables))
    )


def _dynamic_sql_template(node: ast.AST) -> str | None:
    if not isinstance(node, ast.JoinedStr):
        return None
    return "".join(
        part.value if isinstance(part, ast.Constant) and isinstance(part.value, str)
        else "__DYNAMIC_VALUE__"
        for part in node.values
    ).strip()


@dataclass(frozen=True)
class DagSourceFacts:
    dag_ids: list[str]
    exception_types: list[str]
    select_queries: list[str]
    airflow_variables: list[str]
    dynamic_query_detected: bool
    dynamic_select_tables: list[str] | None = None
    literal_numeric_settings: dict[str, int | float] | None = None
    literal_numeric_mappings: dict[str, dict[str, int | float]] | None = None
    read_only_commands: list[str] | None = None
    ssh_connection_ids: list[str] | None = None
    unresolved_ssh_calls: list[str] | None = None
    alert_conditions: list[str] | None = None

    def for_prompt(self) -> dict[str, object]:
        return {
            "dag_ids": self.dag_ids,
            "exception_types": self.exception_types,
            "exact_static_select_queries": self.select_queries,
            "airflow_variables": self.airflow_variables,
            "dynamic_query_detected": self.dynamic_query_detected,
            "dynamic_select_tables": self.dynamic_select_tables or [],
            "literal_numeric_settings": self.literal_numeric_settings or {},
            "literal_numeric_mappings": self.literal_numeric_mappings or {},
            "exact_read_only_commands": self.read_only_commands or [],
            "ssh_connection_ids": self.ssh_connection_ids or [],
            "unresolved_ssh_calls": self.unresolved_ssh_calls or [],
            "alert_conditions": self.alert_conditions or [],
        }


def select_blocks_in_sop(sop: str) -> list[str]:
    """Locate SQL blocks displayed in the SOP for exact-source comparison."""
    lines = sop.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        if not _SELECT.match(lines[index].strip()):
            index += 1
            continue
        parts = [lines[index].strip()]
        index += 1
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("```")
                or re.match(r"^(?:\d+[.)]|[-*])\s", stripped)
            ):
                break
            parts.append(stripped)
            index += 1
        blocks.append(" ".join(" ".join(parts).removesuffix(";").split()))
    return blocks


def analyze_dag_source(source: str) -> DagSourceFacts:
    """Find literal DAG metadata and SELECTs, without resolving imports.

    A dynamic SQL expression is reported as a template, never executed or
    treated as a verbatim query. Literal tables from executed SELECT templates
    may be used to scope a proposed diagnostic for human review.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(
            f"The pasted DAG is not valid Python (line {exc.lineno}): {exc.msg}"
        ) from exc

    bindings: dict[str, str] = {}
    dynamic_bindings: dict[str, str] = {}
    numeric_settings: dict[str, int | float] = {}
    numeric_mappings: dict[str, dict[str, int | float]] = {}
    conflicting_settings: set[str] = set()
    # Numeric configuration is useful context only when it is a module-level
    # literal. Never resolve Airflow Variables or computed runtime values.
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if not isinstance(target, ast.Name) or target.id in conflicting_settings:
                continue
            try:
                literal = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError, MemoryError):
                literal = None
            if type(literal) in (int, float):
                if target.id in numeric_mappings or (
                    target.id in numeric_settings
                    and numeric_settings[target.id] != literal
                ):
                    conflicting_settings.add(target.id)
                else:
                    numeric_settings[target.id] = literal
            elif isinstance(literal, dict) and len(literal) <= 100 and all(
                isinstance(key, str) and type(number) in (int, float)
                for key, number in literal.items()
            ):
                if target.id in numeric_settings or (
                    target.id in numeric_mappings
                    and numeric_mappings[target.id] != literal
                ):
                    conflicting_settings.add(target.id)
                else:
                    numeric_mappings[target.id] = literal
            else:
                conflicting_settings.add(target.id)
            if target.id in conflicting_settings:
                numeric_settings.pop(target.id, None)
                numeric_mappings.pop(target.id, None)
    ambiguous: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = _literal_string(node.value, bindings) if node.value else None
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    template = _dynamic_sql_template(node.value)
                    if template is not None:
                        dynamic_bindings[target.id] = template
                if (
                    isinstance(target, ast.Name)
                    and value is not None
                    and target.id not in ambiguous
                ):
                    # A name with multiple possible values is not a reliable
                    # source of a literal SQL query.
                    previous = bindings.get(target.id)
                    if previous is None or previous == value:
                        bindings[target.id] = value
                    else:
                        bindings.pop(target.id, None)
                        ambiguous.add(target.id)

    dag_ids: list[str] = []
    exceptions: list[str] = []
    queries: list[str] = []
    variables: list[str] = []
    dynamic_query = False
    dynamic_select_tables: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            name = _call_name(node.exc.func)
            if name and name.endswith(("Exception", "Error")):
                exceptions.append(name)

        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node.func)
        if call_name == "insert_job_log_alert":
            # The shared alert logger takes exception_type as its last
            # positional argument. The exception is a string, not a raise.
            for candidate in [
                *([node.args[-1]] if len(node.args) >= 8 else []),
                *(kw.value for kw in node.keywords if kw.arg == "exception_type"),
            ]:
                literal = _literal_string(candidate, bindings)
                if literal and re.fullmatch(
                    r"[A-Za-z_][A-Za-z_0-9]{0,254}", literal
                ) and literal.endswith(("Exception", "Error")):
                    exceptions.append(literal)
        if call_name in {"DAG", "dag"}:
            candidates = [
                keyword.value
                for keyword in node.keywords
                if keyword.arg == "dag_id"
            ]
            if call_name == "DAG" and node.args:
                candidates.append(node.args[0])
            for candidate in candidates:
                literal = _literal_string(candidate, bindings)
                if literal:
                    dag_ids.append(literal)

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "Variable"
            and node.func.attr == "get"
            and node.args
        ):
            variable = _literal_string(node.args[0], bindings)
            if variable:
                variables.append(variable)

        query_nodes = [
            keyword.value
            for keyword in node.keywords
            if keyword.arg in _QUERY_ARGUMENTS
        ]
        if call_name in {"execute", "executemany", "query_database"} and node.args:
            query_nodes.append(node.args[0])

        for query_node in query_nodes:
            literal = _literal_string(query_node, bindings)
            if literal is None:
                dynamic_query = True
                template = (
                    dynamic_bindings.get(query_node.id)
                    if isinstance(query_node, ast.Name)
                    else _dynamic_sql_template(query_node)
                )
                if template and _SELECT.match(template):
                    dynamic_select_tables.update(select_tables(template))
                continue
            cleaned = literal.strip().removesuffix(";").strip()
            if is_read_only_select(cleaned):
                queries.append(cleaned)

    # Some DAGs set sql_query = "SELECT ..." before passing it through a
    # helper. Include these only as candidates for human review.
    for value in bindings.values():
        cleaned = value.strip().removesuffix(";").strip()
        if is_read_only_select(cleaned):
            queries.append(cleaned)

    ssh = analyze_ssh_source(tree)
    return DagSourceFacts(
        dag_ids=_unique(dag_ids),
        exception_types=_unique(exceptions),
        select_queries=_unique(queries),
        airflow_variables=_unique(variables),
        dynamic_query_detected=dynamic_query,
        dynamic_select_tables=sorted(dynamic_select_tables),
        literal_numeric_settings=numeric_settings,
        literal_numeric_mappings=numeric_mappings,
        read_only_commands=ssh.commands,
        ssh_connection_ids=ssh.connection_ids,
        unresolved_ssh_calls=ssh.unresolved_calls,
        alert_conditions=ssh.alert_conditions,
    )
