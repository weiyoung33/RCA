"""Serialize approved RCA actions per target across executor instances."""
from __future__ import annotations

import hashlib
import logging
import re
from functools import wraps


def final_result_status(result):
    if result["success"]:
        return "SUCCEEDED"
    performed = result.get("execution_performed")
    verification = result.get("verification")
    if performed is None or (performed and (
            result.get("timed_out") or verification is None
            or verification.get("state") == "INCONCLUSIVE"
            or verification.get("outcome") == "ACTION_FAILED")):
        return "MANUAL_REVIEW"
    return "FAILED"


def with_target_lock(function):
    @wraps(function)
    def locked(request, settings, database):
        connection = None
        cursor = None
        acquired = False
        entered = False
        try:
            connection = database._connect()
            cursor = connection.cursor()
            key = "rca-target-" + hashlib.sha256(str(request["target_id"]).encode()).hexdigest()[:40]
            cursor.execute("SELECT GET_LOCK(%s, 0)", (key,))
            acquired = cursor.fetchone()[0] == 1
            if not acquired:
                return {"success": False, "execution_performed": False, "exit_code": None,
                        "stdout": "", "stderr": "", "verification": {"outcome": "TARGET_BUSY"},
                        "error": "Another approved RCA action is running on this target. Recheck before creating a new request."}
            entered = True
            return function(request, settings, database)
        except Exception as exc:
            return {"success": False, "execution_performed": None if entered else False, "exit_code": None,
                    "stdout": "", "stderr": "", "verification": None,
                    "error": ("Unexpected execution outcome; inspect before retrying: " if entered
                              else "Executor target lock unavailable: ") + type(exc).__name__}
        finally:
            if cursor is not None:
                try:
                    if acquired:
                        cursor.execute("SELECT RELEASE_LOCK(%s)", (key,))
                        cursor.fetchone()
                except Exception:
                    logging.getLogger("rca.remediation_executor").warning("Target lock cleanup failed; connection will be closed")
                try:
                    cursor.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
    return locked


def validate_check_result(function):
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
