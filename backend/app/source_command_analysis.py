"""Extract potential read-only SSH diagnostics from pasted Python source.

Only literal data flows are expanded. The DAG is never imported or executed.
An unresolvable expression never becomes a command.
"""

from __future__ import annotations

import ast
import re
import shlex
from dataclasses import dataclass


_MAX_VALUES = 30
_MAX_COMMAND = 2000
_READ_ONLY_TOOLS = {
    "pgrep", "ps", "stat", "df", "uptime", "hostname",
    "wc", "ls", "grep", "head", "tail", "cat",
}
_HOSTNAME_READ_ONLY_OPTIONS = {
    "-a", "--alias", "-A", "--all-fqdns", "-d", "--domain",
    "-f", "--fqdn", "-i", "--ip-address", "-I", "--all-ip-addresses",
    "-s", "--short", "-y", "--yp", "--help", "--version",
}
_FORBIDDEN_SHELL = re.compile(r"[\n\r;&|<>$]")
_SHELL_LINE = re.compile(
    r"^(?:sudo|kill|pkill|rm|bash|sh|python\d*|nohup|systemctl|"
    r"pgrep|ps|stat|df|uptime|hostname|wc|ls|grep|head|tail|cat)\b"
)
_PLACEHOLDER = re.compile(r"<[A-Za-z_][A-Za-z0-9_-]*>")


def is_read_only_ssh_command(command: str) -> bool:
    """Conservatively accept one simple diagnostic, never a shell program."""
    if (not command or len(command) > _MAX_COMMAND
            or _FORBIDDEN_SHELL.search(command) or chr(96) in command):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts or not parts[0].isascii():
        return False
    tool = parts[0].rsplit("/", 1)[-1]
    if tool == "systemctl":
        return len(parts) >= 2 and parts[1] in {"status", "is-active", "is-enabled", "show"}
    if tool == "hostname":
        # A bare name or flags such as -F/--file can change the host name.
        return len(parts) == 1 or (len(parts) == 2 and parts[1] in _HOSTNAME_READ_ONLY_OPTIONS)
    if tool not in _READ_ONLY_TOOLS:
        return False
    if any(part in {"-exec", "-execdir", "-delete", "-ok", "-f"}
           for part in parts[1:]) and tool != "pgrep":
        return False
    return True


def unsafe_sop_shell_lines(sop: str) -> list[str]:
    """Catch standalone shell instructions the Verifier must not run."""
    unsafe = []
    for line in sop.splitlines():
        candidate = line.strip().strip(chr(96)).strip()
        if _SHELL_LINE.match(candidate) and not is_read_only_ssh_command(candidate):
            unsafe.append(candidate)
    return unsafe


def placeholder_sop_shell_lines(sop: str) -> list[str]:
    """Identify command-shaped lines with unexpanded symbolic arguments."""
    return [
        candidate
        for line in sop.splitlines()
        if (candidate := line.strip().strip(chr(96)).strip())
        and _SHELL_LINE.match(candidate)
        and _PLACEHOLDER.search(candidate)
    ]


def replace_source_command_placeholders(
    sop: str, source_commands: list[str],
) -> str:
    """Replace only shorthand that the traced exact commands fully cover."""
    if not source_commands:
        return sop
    lines = []
    for line in sop.splitlines():
        candidate = line.strip().strip(chr(96)).strip()
        shorthand = re.fullmatch(
            r"(.+?)\s+<[A-Za-z_][A-Za-z0-9_-]*>", candidate,
        )
        if shorthand and _SHELL_LINE.match(candidate):
            prefix = shorthand.group(1)
            if any(command.startswith(prefix + " ") for command in source_commands):
                lines.append(
                    "See the exact source-derived command for each item "
                    "in the diagnostic checks below."
                )
                continue
        lines.append(line)
    return "\n".join(lines)


def remove_credential_details_from_sop(sop: str) -> str:
    """Keep activation secrets and credential identifiers out of diagnostics."""
    lines = []
    in_prerequisites = False
    for line in sop.splitlines():
        stripped = line.strip()
        if re.match(r"^#{1,2}\s", stripped):
            in_prerequisites = "activation prerequisites" in stripped.lower()
        if in_prerequisites and stripped.startswith(("-", "*")) and re.search(
            r"(?i)(?:credential\s+(?:plan|name)\s*:|"
            r"username\s*:|password\s*:|secret\s+is\s+required|"
            r"[\x60][^\x60]+[\x60]\s*\?\s*no\b)",
            stripped,
        ):
            continue
        lines.append(line)
    return "\n".join(lines)


@dataclass(frozen=True)
class SshSourceFacts:
    commands: list[str]
    unresolved_calls: list[str]
    connection_ids: list[str]
    alert_conditions: list[str]


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _static_value(node: ast.AST, env: dict[str, object]) -> object | None:
    """Resolve bounded literals and string building, without eval()."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > _MAX_VALUES:
            return None
        values = [_static_value(item, env) for item in node.elts]
        return values if all(isinstance(item, (str, int, float)) for item in values) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_value(node.left, env), _static_value(node.right, env)
        if isinstance(left, str) and isinstance(right, str):
            return (left + right)[:_MAX_COMMAND + 1]
    if isinstance(node, ast.JoinedStr):
        pieces = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if part.format_spec or part.conversion not in (-1, 115):
                    return None
                value = _static_value(part.value, env)
            else:
                value = _static_value(part, env)
            if not isinstance(value, (str, int, float)):
                return None
            pieces.append(str(value))
        return "".join(pieces)[:_MAX_COMMAND + 1]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format" and not node.keywords):
        fmt = _static_value(node.func.value, env)
        args = [_static_value(arg, env) for arg in node.args]
        if isinstance(fmt, str) and all(isinstance(arg, (str, int, float)) for arg in args):
            try:
                return fmt.format(*args)[:_MAX_COMMAND + 1]
            except (ValueError, IndexError, KeyError, AttributeError):
                return None
    return None


def analyze_ssh_source(tree: ast.Module) -> SshSourceFacts:
    """Trace literal assignments and finite loops to SSH execution sites."""
    commands: list[str] = []
    unresolved: list[str] = []
    connections: list[str] = []
    conditions: list[str] = []
    module_env: dict[str, object] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            value = _static_value(statement.value, module_env)
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    module_env[target.id] = value
    mutated_names: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.attr in {"append", "extend", "insert", "pop",
                                       "remove", "clear", "sort", "reverse"}):
            mutated_names.add(node.func.value.id)
            module_env.pop(node.func.value.id, None)
        elif isinstance(node, (ast.AugAssign, ast.Delete)):
            targets = [node.target] if isinstance(node, ast.AugAssign) else node.targets
            for target in targets:
                if isinstance(target, ast.Name):
                    mutated_names.add(target.id)
                    module_env.pop(target.id, None)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "SSHHook":
            candidates = [kw.value for kw in node.keywords if kw.arg == "ssh_conn_id"]
            for candidate in candidates:
                value = _static_value(candidate, module_env)
                if isinstance(value, str) and value not in connections:
                    connections.append(value)
        if isinstance(node, ast.If) and any(
            isinstance(child, ast.Call)
            and _call_name(child.func) == "insert_job_log_alert"
            for item in node.body for child in ast.walk(item)
        ):
            condition = ast.unparse(node.test)
            if condition not in conditions:
                conditions.append(condition)

    def capture(call: ast.Call, env: dict[str, object]) -> None:
        name = _call_name(call.func)
        if name not in {"exec_command", "SSHOperator", "run_ssh_command"}:
            return
        candidates = [kw.value for kw in call.keywords if kw.arg == "command"]
        if name != "SSHOperator" and call.args:
            candidates.append(call.args[0])
        if not candidates:
            unresolved.append(name)
            return
        for candidate in candidates:
            value = _static_value(candidate, env)
            if isinstance(value, str) and is_read_only_ssh_command(value):
                if value not in commands:
                    commands.append(value)
            else:
                detail = f"{name} at line {call.lineno}"
                if detail not in unresolved:
                    unresolved.append(detail)

    def visit(statements: list[ast.stmt], env: dict[str, object]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(statement.body, dict(module_env))
            elif isinstance(statement, ast.Assign):
                value = _static_value(statement.value, env)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = None if target.id in mutated_names else value
                if isinstance(statement.value, ast.Call):
                    capture(statement.value, env)
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                env[statement.target.id] = _static_value(statement.value, env)
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                capture(statement.value, env)
            elif isinstance(statement, ast.For):
                values = _static_value(statement.iter, env)
                if isinstance(statement.target, ast.Name) and isinstance(values, list):
                    for value in values:
                        child = dict(env)
                        child[statement.target.id] = value
                        visit(statement.body, child)
                else:
                    visit(statement.body, dict(env))
                visit(statement.orelse, dict(env))
            elif isinstance(statement, ast.If):
                visit(statement.body, dict(env))
                visit(statement.orelse, dict(env))
            elif isinstance(statement, (ast.With, ast.Try)):
                visit(statement.body, dict(env))
                if isinstance(statement, ast.Try):
                    for handler in statement.handlers:
                        visit(handler.body, dict(env))
                    visit(statement.orelse, dict(env))
                    visit(statement.finalbody, dict(env))
            elif isinstance(statement, ast.Return) and isinstance(statement.value, ast.Call):
                capture(statement.value, env)

    visit(tree.body, dict(module_env))
    return SshSourceFacts(commands, unresolved, connections, conditions)
