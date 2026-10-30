"""Patch required-diagnostic scheduling in the existing structured Verifier.

Preview: python verifier_diagnostic_update/scripts/install_required_diagnostics.py .
Apply:   python verifier_diagnostic_update/scripts/install_required_diagnostics.py . --apply
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime
import os
from pathlib import Path
import shutil
import tempfile

MARKER = "RCA_REQUIRED_DIAGNOSTICS_V1"


def position(source, node, end=False):
    lines = source.splitlines(keepends=True)
    number = node.end_lineno if end else node.lineno
    column = node.end_col_offset if end else node.col_offset
    return sum(map(len, lines[:number - 1])) + len(lines[number - 1].encode()[:column].decode())


def patch_source(source, helper):
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    needed = {"run_verifier_with_findings", "_execute_tool", "_normalized_final", "_call_llm",
              "_target_is_in_sop", "_database_query_is_allowed", "_ssh_command_is_allowed",
              "_sop_requires_diagnostic", "_prompt_input", "_normalized_text", "_text_items"}
    if not needed.issubset(functions):
        raise ValueError("The structured Verifier integration points differ; no file was changed.")
    run = functions["run_verifier_with_findings"]
    segment = ast.get_source_segment(source, run)
    if MARKER in source:
        if helper.strip() not in source or "_rca_diag_next_instruction(" not in segment:
            raise ValueError("A different or partial diagnostic update exists; no file was changed.")
        if segment.count("_rca_diag_guard_final(") != 2 or "_rca_diag_bootstrap(" not in segment:
            raise ValueError("The diagnostic update integration is incomplete; no file was changed.")
        return source
    if [a.arg for a in run.args.args] != ["incident_error_message", "proposed_rca", "proposed_fix",
                                         "raw_db_sop", "initial_tool_history"]:
        raise ValueError("Unexpected Verifier public signature; no file was changed.")
    anchors = [n for n in run.body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "required_ssh_checks" for t in n.targets)]
    if not anchors:
        if "_fixed_initial_sop_ssh_checks(" in segment:
            raise ValueError("The SSH scheduler differs; no file was changed.")
        # Earlier structured versions have a database-only bootstrap. Preserve
        # their reporting and scope extensions while updating this same flow.
        anchors = [n for n in run.body if isinstance(n, ast.If)
                   and isinstance(n.test, ast.UnaryOp) and isinstance(n.test.op, ast.Not)
                   and isinstance(n.test.operand, ast.Name) and n.test.operand.id == "history"
                   and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                           and c.func.id == "_required_first_sop_database_check" for c in ast.walk(n))]
    loops = [n for n in run.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name)
             and n.target.id == "step"]
    if len(anchors) != 1 or len(loops) != 1:
        raise ValueError("Cannot identify the existing diagnostic scheduler; no file was changed.")
    loop = loops[0]
    if position(source, anchors[0]) >= position(source, loop):
        raise ValueError("The initial scheduler no longer precedes model decisions; no file was changed.")
    calls = [n for n in ast.walk(loop) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "_call_llm"]
    guards = [n for n in ast.walk(loop) if isinstance(n, ast.If)
              and "The Verifier returned a final answer without the SOP-required diagnostic"
              in (ast.get_source_segment(source, n) or "")
              and isinstance(n.test, ast.BoolOp)]
    finals = [n for n in ast.walk(run) if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Name) and n.func.id == "_normalized_final"]
    if len(calls) != 1 or len(guards) != 1 or len(finals) != 2:
        raise ValueError("The model/final-response flow differs; no file was changed.")
    edits = [(position(source, run), position(source, run), helper.strip() + "\n\n\n")]
    begin = source.rfind("\n", 0, position(source, anchors[0])) + 1
    finish = source.rfind("\n", 0, position(source, loop)) + 1
    edits.append((begin, finish, '''    try:
        required_checks = _rca_diag_bootstrap(raw_db_sop, history)
    except _RcaDiagnosticSelectionError as exc:
        return fallback(str(exc))
    diagnostic_repair_state = {"used": 0}

'''))
    call = calls[0]
    edits.append((position(source, call), position(source, call, True),
                  "_rca_diag_next_instruction(incident_context, raw_db_sop, history, "
                  "required_checks, diagnostic_repair_state)"))
    # Handle exhausted local repairs alongside (not instead of) the existing
    # transient network/model retry handler.
    model_try = next((n for n in loop.body if isinstance(n, ast.Try) and any(
        c is call for c in ast.walk(n))), None)
    if model_try is None or not model_try.handlers:
        raise ValueError("The model retry handler differs; no file was changed.")
    handler_end = position(source, model_try.handlers[-1], True)
    edits.append((handler_end, handler_end,
                  "\n        except _RcaDiagnosticSelectionError as exc:\n"
                  "            return fallback(str(exc))"))
    guard = guards[0]
    guard_begin = source.rfind("\n", 0, position(source, guard)) + 1
    edits.append((guard_begin, position(source, guard, True), ""))
    for call in finals:
        if len(call.args) != 4 or not isinstance(call.args[0], ast.Name):
            raise ValueError("The final normalizer call differs; no file was changed.")
        arg = call.args[0]
        edits.append((position(source, arg), position(source, arg, True),
                      "_rca_diag_guard_final(" + arg.id + ", history, required_checks)"))
    for begin, finish, replacement in sorted(edits, reverse=True):
        source = source[:begin] + replacement + source[finish:]
    ast.parse(source, feature_version=(3, 9))
    compile(source, "verifier_agent.py", "exec")
    return source


def install(path, apply=False):
    before = path.read_bytes()
    original = before.decode("utf-8-sig").replace("\r\n", "\n")
    helper = (Path(__file__).resolve().parents[1] / "patches/required_diagnostics.py").read_text(encoding="utf-8")
    updated = patch_source(original, helper)
    if updated == original:
        print("Already installed: " + str(path))
        return
    print("Prepared: " + str(path))
    print("Changes only diagnostic scheduling and bounded local correction in this existing file.")
    if not apply:
        print("Read-only preview. Add --apply to install with a timestamped backup.")
        return
    content = updated.replace("\n", "\r\n" if b"\r\n" in before else "\n").encode("utf-8")
    if before.startswith(b"\xef\xbb\xbf"):
        content = b"\xef\xbb\xbf" + content
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".rca-diagnostic-")
    backup = path.with_name(path.name + ".before_required_diagnostics_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f") + ".bak")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        identity = path.stat()
        shutil.copymode(path, temporary)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(temporary, identity.st_uid, identity.st_gid)
        if path.read_bytes() != before:
            raise ValueError("The Verifier changed while preparing; no source was replaced.")
        shutil.copy2(path, backup)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(backup, identity.st_uid, identity.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Updated: " + str(path))
    print("Backup: " + str(backup))
    print("Restart pipeline_runner.py. Backend, frontend and executor are unchanged.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    path = args.project_root.resolve() / "agents/verifier_agent.py"
    if not path.is_file():
        parser.error("Choose the application project root containing agents/verifier_agent.py")
    try:
        install(path, args.apply)
    except (ValueError, SyntaxError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
