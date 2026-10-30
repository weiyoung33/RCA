"""Fix execution-mode validation of configured unhealthy command exits.

From the application root (Python 3.9+):
    python fix_executor_prechecks.py .           # preview
    python fix_executor_prechecks.py . --apply   # backup and patch
    python fix_executor_prechecks.py --self-test # offline checks only

Only agents/managed_executor_lock.py changes. The target-lock implementation,
catalog, approval logic and action commands are preserved. Restart the
remediation_executor.py process after deploying the changed runtime file.
This installer never connects to SSH, the database or any production service.
"""
from __future__ import annotations

import argparse
import ast
import copy
from datetime import datetime
from functools import wraps
import io
import contextlib
import os
from pathlib import Path
import re
import shutil
import tempfile
from types import SimpleNamespace
import unittest


OLD_FUNCTION = '''def validate_check_result(function):
    @wraps(function)
    def checked(client, check, max_output_bytes):
        result = function(client, check, max_output_bytes)
        output = result.get("stdout", "").strip()
        invalid = bool(result.get("timed_out") or result.get("output_truncated"))
        if getattr(check, "require_stdout", False) and not output:
            invalid = True
        if result.get("state") == "UNHEALTHY" and output:
            pattern = getattr(check, "unhealthy_stdout_regex", None)
            if pattern and not re.fullmatch(pattern, output):
                invalid = True
        if invalid:
            result.update(healthy=False, state="INCONCLUSIVE")
        return result
    return checked
'''

NEW_FUNCTION = '''def validate_check_result(function):
    # RCA_EXPLICIT_UNHEALTHY_EXIT_V1
    @wraps(function)
    def checked(client, check, max_output_bytes):
        result = function(client, check, max_output_bytes)
        output = result.get("stdout", "").strip()
        invalid = bool(result.get("timed_out") or result.get("output_truncated"))
        pattern = getattr(check, "unhealthy_stdout_regex", None)
        exit_code = result.get("exit_code")
        # An exit explicitly configured as unhealthy can prove that state
        # without stdout, unless the catalog also requires an output pattern.
        # Never upgrade an existing INCONCLUSIVE result or infer a global
        # meaning for exit code 1 (or for any other command's exit code).
        exit_proves_unhealthy = (
            result.get("state") == "UNHEALTHY"
            and type(exit_code) is int
            and exit_code in getattr(check, "unhealthy_exit_codes", ())
            and exit_code not in getattr(check, "expected_exit_codes", ())
            and pattern is None
        )
        if (getattr(check, "require_stdout", False) and not output
                and not exit_proves_unhealthy):
            invalid = True
        if result.get("state") == "UNHEALTHY" and pattern is not None:
            if not re.fullmatch(pattern, output):
                invalid = True
        if invalid:
            result.update(healthy=False, state="INCONCLUSIVE")
        return result
    return checked
'''


def _function(source):
    matches = [node for node in ast.parse(source).body
               if isinstance(node, ast.FunctionDef) and node.name == "validate_check_result"]
    if len(matches) != 1:
        raise ValueError("Expected one validate_check_result function; no file was changed.")
    return matches[0]


def patch_source(source):
    function = _function(source)
    shape = ast.dump(function, include_attributes=False)
    if shape == ast.dump(_function(NEW_FUNCTION), include_attributes=False):
        return source
    if shape != ast.dump(_function(OLD_FUNCTION), include_attributes=False):
        raise ValueError("The installed validator differs from this known version. "
                         "No file was changed; review its validate_check_result function.")
    lines = source.splitlines(keepends=True)
    updated = "".join(lines[:function.lineno - 1]) + NEW_FUNCTION.rstrip() + "\n" + "".join(lines[function.end_lineno:])
    ast.parse(updated, feature_version=(3, 9))
    compile(updated, "managed_executor_lock.py", "exec")
    return updated


def install(root, apply=False):
    path = root.resolve() / "agents/managed_executor_lock.py"
    if not path.is_file():
        raise ValueError("Choose the application root containing agents/managed_executor_lock.py")
    before = path.read_bytes()
    source = before.decode("utf-8-sig").replace("\r\n", "\n")
    updated = patch_source(source)
    if updated == source:
        print("Already fixed: " + str(path))
        return
    print("Prepared: " + str(path))
    print("Only validate_check_result changes; target locking and approvals are preserved.")
    if not apply:
        print("Preview only. Run again with --apply to patch with a backup.")
        return
    after = updated.replace("\n", "\r\n" if b"\r\n" in before else "\n").encode("utf-8")
    if before.startswith(b"\xef\xbb\xbf"):
        after = b"\xef\xbb\xbf" + after
    identity = path.stat()
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".rca-precheck-")
    backup = path.with_name(path.name + ".before_unhealthy_exit_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f") + ".bak")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        shutil.copymode(path, temporary)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(temporary, identity.st_uid, identity.st_gid)
        if path.read_bytes() != before:
            raise ValueError("The source changed while preparing; no source was replaced.")
        shutil.copy2(path, backup)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(backup, identity.st_uid, identity.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Updated: " + str(path))
    print("Backup: " + str(backup))
    print("Deploy this runtime file and restart remediation_executor.py.")
    print("Existing failed requests are unchanged; validate with a new approved request.")


def _evaluate(result, **overrides):
    namespace = {"wraps": wraps, "re": re}
    exec(NEW_FUNCTION, namespace)
    check = SimpleNamespace(require_stdout=True, unhealthy_exit_codes=(1,),
                            expected_exit_codes=(0,), unhealthy_stdout_regex=None)
    for key, value in overrides.items():
        setattr(check, key, value)
    def base(*_):
        return copy.deepcopy(result)
    return namespace["validate_check_result"](base)(None, check, 4096)


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.result = {"state": "UNHEALTHY", "healthy": False, "exit_code": 1,
                       "stdout": "", "stderr": "", "timed_out": False, "output_truncated": False}

    def test_configured_unhealthy_exit_without_output(self):
        self.assertEqual(_evaluate(self.result)["state"], "UNHEALTHY")

    def test_other_configured_unhealthy_exit_is_generic(self):
        self.result["exit_code"] = 3
        self.assertEqual(_evaluate(self.result, unhealthy_exit_codes=(3,))["state"], "UNHEALTHY")

    def test_unconfigured_exit_does_not_bypass_output_requirement(self):
        self.assertEqual(_evaluate(self.result, unhealthy_exit_codes=())["state"], "INCONCLUSIVE")

    def test_existing_inconclusive_is_not_upgraded(self):
        self.result["state"] = "INCONCLUSIVE"
        self.assertEqual(_evaluate(self.result)["state"], "INCONCLUSIVE")

    def test_healthy_empty_output_still_invalid(self):
        self.result.update(state="HEALTHY", healthy=True, exit_code=0)
        self.assertEqual(_evaluate(self.result)["state"], "INCONCLUSIVE")

    def test_healthy_complete_output_preserved(self):
        self.result.update(state="HEALTHY", healthy=True, exit_code=0, stdout="123 python service.py")
        self.assertEqual(_evaluate(self.result)["state"], "HEALTHY")

    def test_timeout_still_invalid(self):
        self.result["timed_out"] = True
        self.assertEqual(_evaluate(self.result)["state"], "INCONCLUSIVE")

    def test_truncation_still_invalid(self):
        self.result["output_truncated"] = True
        self.assertEqual(_evaluate(self.result)["state"], "INCONCLUSIVE")

    def test_required_unhealthy_pattern_not_waived_for_empty_output(self):
        self.assertEqual(_evaluate(self.result, unhealthy_stdout_regex=r"^0$")["state"], "INCONCLUSIVE")

    def test_unhealthy_pattern_matches_valid_output(self):
        self.result.update(exit_code=0, stdout="0")
        self.assertEqual(_evaluate(self.result, unhealthy_stdout_regex=r"^0$")["state"], "UNHEALTHY")

    def test_unhealthy_pattern_rejects_unexpected_output(self):
        self.result["stdout"] = "unexpected error"
        self.assertEqual(_evaluate(self.result, unhealthy_stdout_regex=r"^0$")["state"], "INCONCLUSIVE")

    def test_http_unhealthy_result_without_command_stdout_requirement(self):
        self.result.update(exit_code=7, stdout="\n__RCA_HTTP_STATUS__:000\n")
        self.assertEqual(_evaluate(self.result, require_stdout=False, unhealthy_exit_codes=())["state"], "UNHEALTHY")

    def test_overlapping_exit_contract_does_not_waive_stdout(self):
        self.assertEqual(_evaluate(self.result, expected_exit_codes=(0, 1))["state"], "INCONCLUSIVE")

    def test_unknown_exit_type_cannot_prove_unhealthy(self):
        self.result["exit_code"] = True
        self.assertEqual(_evaluate(self.result)["state"], "INCONCLUSIVE")

    def test_patch_preserves_surrounding_code_and_is_idempotent(self):
        source = "# before\n" + OLD_FUNCTION + "\nLOCK_SENTINEL = 'preserved'\n"
        updated = patch_source(source)
        self.assertTrue(updated.startswith("# before\n"))
        self.assertTrue(updated.endswith("LOCK_SENTINEL = 'preserved'\n"))
        self.assertEqual(patch_source(updated), updated)

    def test_different_version_is_refused(self):
        with self.assertRaises(ValueError):
            patch_source(OLD_FUNCTION.replace('result.get("timed_out")', 'False'))

    def test_python39_syntax(self):
        ast.parse(NEW_FUNCTION, feature_version=(3, 9))

    def test_backup_preview_crlf_bom_and_apply(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "agents").mkdir()
            path = root / "agents/managed_executor_lock.py"
            before = b"\xef\xbb\xbf" + OLD_FUNCTION.replace("\n", "\r\n").encode()
            path.write_bytes(before)
            with contextlib.redirect_stdout(io.StringIO()):
                install(root)
                self.assertEqual(path.read_bytes(), before)
                install(root, True)
                updated = path.read_bytes()
                install(root, True)
            self.assertEqual(path.read_bytes(), updated)
            self.assertTrue(updated.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\n", updated.replace(b"\r\n", b""))
            backups = list((root / "agents").glob("*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineTests))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    try:
        install(args.project_root, args.apply)
    except (ValueError, SyntaxError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
