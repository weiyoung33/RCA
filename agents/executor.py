from __future__ import annotations

from .managed_executor_lock import with_target_lock, validate_check_result

import logging
import re
import shlex
import signal
import time
from datetime import datetime, timezone
from typing import Any, Optional, Union

import paramiko

from .config import ExecutorSettings
from .action_registry import (
    ActionDefinition,
    CommandCheck,
    HttpCheck,
    action_from_catalog_row,
    enabled_action_ids,
    estimated_max_runtime_seconds,
    validate_action_rows,
)
from .database import RemediationDatabase
from .target_registry import (
    ResolvedSshTarget,
    install_pinned_host_key,
    resolve_ssh_target,
)


LOGGER = logging.getLogger("rca.remediation_executor")
HTTP_STATUS_MARKER = "__RCA_HTTP_STATUS__"
CURL_UNHEALTHY_EXIT_CODES = frozenset({7, 28, 52, 56})


def _append_limited(buffer: bytearray, chunk: bytes, limit: int) -> None:
    remaining = limit - len(buffer)
    if remaining > 0:
        buffer.extend(chunk[:remaining])


def execute_fixed_command(
    client: paramiko.SSHClient,
    command: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Execute one validated catalog command and capture bounded UTF-8 output."""

    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise RuntimeError("SSH transport is not active")

    channel = transport.open_session(timeout=10)
    channel.exec_command(command)
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False

    while not channel.exit_status_ready():
        if channel.recv_ready():
            _append_limited(stdout, channel.recv(32768), max_output_bytes)
        if channel.recv_stderr_ready():
            _append_limited(stderr, channel.recv_stderr(32768), max_output_bytes)
        if time.monotonic() >= deadline:
            timed_out = True
            channel.close()
            break
        time.sleep(0.05)

    if not timed_out:
        while channel.recv_ready():
            _append_limited(stdout, channel.recv(32768), max_output_bytes)
        while channel.recv_stderr_ready():
            _append_limited(stderr, channel.recv_stderr(32768), max_output_bytes)
        exit_code = channel.recv_exit_status()
    else:
        exit_code = 124
        _append_limited(
            stderr,
            f"\nCommand timed out after {timeout_seconds} seconds".encode(),
            max_output_bytes,
        )

    return {
        "exit_code": exit_code,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "timed_out": timed_out,
        "output_truncated": (
            len(stdout) >= max_output_bytes or len(stderr) >= max_output_bytes
        ),
    }


def create_ssh_client(
    action: ActionDefinition,
    _settings: ExecutorSettings,
) -> tuple[paramiko.SSHClient, ResolvedSshTarget]:
    target = resolve_ssh_target(action.target_id, "EXECUTOR")
    client = paramiko.SSHClient()
    install_pinned_host_key(client, target)
    connection_options: dict[str, Any] = {
        "hostname": target.hostname,
        "port": target.port,
        "username": target.username,
        "password": target.password,
        "look_for_keys": False,
        "allow_agent": False,
        "timeout": 10,
        "auth_timeout": 10,
        "banner_timeout": 10,
    }
    client.connect(
        **connection_options,
    )
    return client, target


def _http_command(check: HttpCheck) -> str:
    marker = f"\\n{HTTP_STATUS_MARKER}:%{{http_code}}\\n"
    return " ".join(
        (
            "curl --silent --show-error --include",
            f"--max-time {int(check.timeout_seconds)}",
            f"--write-out {shlex.quote(marker)}",
            shlex.quote(check.url),
        )
    )


@validate_check_result
def run_check(
    client: paramiko.SSHClient,
    check: Union[CommandCheck, HttpCheck],
    max_output_bytes: int,
) -> dict[str, Any]:
    if isinstance(check, CommandCheck):
        result = execute_fixed_command(
            client,
            check.command,
            check.timeout_seconds,
            max_output_bytes,
        )
        stdout = result["stdout"].strip()
        if result["timed_out"]:
            state = "INCONCLUSIVE"
        elif result["exit_code"] in check.expected_exit_codes:
            healthy_pattern = check.healthy_stdout_regex
            unhealthy_pattern = check.unhealthy_stdout_regex
            if healthy_pattern is not None:
                if re.fullmatch(healthy_pattern, stdout):
                    state = "HEALTHY"
                elif (
                    unhealthy_pattern is not None
                    and re.fullmatch(unhealthy_pattern, stdout)
                ):
                    state = "UNHEALTHY"
                else:
                    state = "INCONCLUSIVE"
            elif (
                unhealthy_pattern is not None
                and re.fullmatch(unhealthy_pattern, stdout)
            ):
                state = "UNHEALTHY"
            elif check.require_stdout and not stdout:
                state = "INCONCLUSIVE"
            else:
                state = "HEALTHY"
        elif result["exit_code"] in check.unhealthy_exit_codes:
            state = "UNHEALTHY"
        else:
            state = "INCONCLUSIVE"
        result.update(
            {
                "name": check.name,
                "kind": "command",
                "healthy": state == "HEALTHY",
                "state": state,
                "expected_exit_codes": list(check.expected_exit_codes),
                "unhealthy_exit_codes": list(check.unhealthy_exit_codes),
            }
        )
        return result

    result = execute_fixed_command(
        client,
        _http_command(check),
        check.timeout_seconds + 5,
        max_output_bytes,
    )
    status_code: Optional[int] = None
    marker = f"{HTTP_STATUS_MARKER}:"
    if marker in result["stdout"]:
        status_text = result["stdout"].rsplit(marker, 1)[1].strip().splitlines()[0]
        try:
            status_code = int(status_text)
        except ValueError:
            status_code = None
    if result["timed_out"]:
        state = "INCONCLUSIVE"
    elif result["exit_code"] == 0 and status_code is not None:
        state = (
            "HEALTHY"
            if status_code in check.expected_status_codes
            else "UNHEALTHY"
        )
    elif result["exit_code"] in CURL_UNHEALTHY_EXIT_CODES:
        state = "UNHEALTHY"
    else:
        state = "INCONCLUSIVE"
    result.update(
        {
            "name": check.name,
            "kind": "http",
            "status_code": status_code,
            "healthy": state == "HEALTHY",
            "state": state,
            "expected_status_codes": list(check.expected_status_codes),
        }
    )
    return result


def _overall_check_state(checks: list[dict[str, Any]]) -> str:
    states = [str(check.get("state") or "INCONCLUSIVE") for check in checks]
    if "INCONCLUSIVE" in states:
        return "INCONCLUSIVE"
    if "UNHEALTHY" in states:
        return "UNHEALTHY"
    return "HEALTHY"


def check_current_state(
    client: paramiko.SSHClient,
    action: ActionDefinition,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Run one live, read-only verification immediately before execution."""

    checks = [
        run_check(client, check, max_output_bytes)
        for check in action.precheck_checks
    ]
    state = _overall_check_state(checks)
    return {
        "healthy": state == "HEALTHY",
        "state": state,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


def verify_action(
    client: paramiko.SSHClient,
    action: ActionDefinition,
    max_output_bytes: int,
) -> dict[str, Any]:
    last_checks: list[dict[str, Any]] = []
    for attempt in range(1, action.verification_attempts + 1):
        last_checks = [
            run_check(client, check, max_output_bytes)
            for check in action.postcheck_checks
        ]
        state = _overall_check_state(last_checks)
        if state == "HEALTHY":
            return {
                "healthy": True,
                "state": state,
                "attempts_used": attempt,
                "checks": last_checks,
            }
        if attempt < action.verification_attempts:
            time.sleep(action.verification_delay_seconds)

    final_state = _overall_check_state(last_checks)
    return {
        "healthy": final_state == "HEALTHY",
        "state": final_state,
        "attempts_used": action.verification_attempts,
        "checks": last_checks,
    }


def validate_request_definition(
    request: dict[str, Any],
) -> ActionDefinition:
    if request.get("lifecycle_status") != "ACTIVE":
        raise RuntimeError(f"Action {request['action_id']} is not ACTIVE")

    action = action_from_catalog_row(
        {
            "action_id": request["action_id"],
            "component_id": request["catalog_component_id"],
            "target_id": request["catalog_target_id"],
            "implementation_version": request[
                "catalog_implementation_version"
            ],
            "executor_type": request["executor_type"],
            "execution_spec": request["execution_spec"],
        }
    )
    if request["component_id_snapshot"] != action.component_id:
        raise RuntimeError(
            "Component mismatch: "
            f"request={request['component_id_snapshot']}, "
            f"registry={action.component_id}"
        )
    if request["target_id"] != action.target_id:
        raise RuntimeError(
            f"Target mismatch: request={request['target_id']}, registry={action.target_id}"
        )
    if (
        request["implementation_version_snapshot"]
        != action.implementation_version
    ):
        raise RuntimeError(
            "Action implementation changed after approval; a new request is required"
        )
    return action


@with_target_lock
def run_registered_action(
    request: dict[str, Any],
    settings: ExecutorSettings,
    database: RemediationDatabase,
) -> dict[str, Any]:
    try:
        action = validate_request_definition(request)
    except Exception as exc:
        return {
            "success": False,
            "execution_performed": False,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "verification": None,
            "error": str(exc),
        }

    maximum_runtime = estimated_max_runtime_seconds(action)
    if settings.lease_seconds <= maximum_runtime + 30:
        return {
            "success": False,
            "execution_performed": False,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "verification": None,
            "error": (
                "EXECUTOR_LEASE_SECONDS must exceed the maximum runtime for "
                f"{action.action_id} ({maximum_runtime} seconds) by at least "
                "30 seconds"
            ),
        }

    client: Optional[paramiko.SSHClient] = None
    execution_performed = False
    execution: dict[str, Any] = {
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "output_truncated": False,
    }
    try:
        client, target = create_ssh_client(action, settings)
        precheck = check_current_state(
            client,
            action,
            settings.max_output_bytes,
        )

        if precheck["state"] == "HEALTHY":
            LOGGER.info(
                "Skipping action %s because target %s is already healthy",
                action.action_id,
                action.target_id,
            )
            return {
                "success": True,
                "execution_performed": False,
                **execution,
                "verification": {
                    **precheck,
                    "outcome": "ALREADY_HEALTHY",
                    "execution_performed": False,
                    "precheck": precheck,
                },
                "error": None,
            }

        if precheck["state"] == "INCONCLUSIVE":
            return {
                "success": False,
                "execution_performed": False,
                **execution,
                "verification": {
                    **precheck,
                    "outcome": "PRECHECK_INCONCLUSIVE",
                    "execution_performed": False,
                    "precheck": precheck,
                },
                "error": (
                    "The live pre-action check was inconclusive. "
                    "No command was executed."
                ),
            }

        # An approval may predate a source detail appended to the same batch.
        # Re-read the incident and source rows after the live precheck, just
        # before sending the registered state-changing command over SSH.
        try:
            database.assert_current_evidence(request)
        except Exception as exc:
            LOGGER.warning(
                "Skipping action %s for remediation %s: %s",
                action.action_id,
                request["remediation_id"],
                exc,
            )
            return {
                "success": False,
                "execution_performed": False,
                **execution,
                "verification": {
                    "healthy": False,
                    "state": "INCONCLUSIVE",
                    "outcome": "EVIDENCE_STALE_OR_UNAVAILABLE",
                    "execution_performed": False,
                    "precheck": precheck,
                    "checks": [],
                },
                "error": str(exc),
            }

        LOGGER.info(
            "Executing registered action %s version %s on target %s (%s)",
            action.action_id,
            action.implementation_version,
            action.target_id,
            target.hostname,
        )
        execution_performed = True
        execution = execute_fixed_command(
            client,
            action.command,
            action.command_timeout_seconds,
            settings.max_output_bytes,
        )
        if execution["exit_code"] != 0:
            return {
                "success": False,
                "execution_performed": True,
                **execution,
                "verification": {
                    "healthy": False,
                    "state": "UNHEALTHY",
                    "outcome": "ACTION_FAILED",
                    "execution_performed": True,
                    "precheck": precheck,
                    "checks": [],
                },
                "error": "The registered action returned a non-zero exit status",
            }

        verification = verify_action(
            client,
            action,
            settings.max_output_bytes,
        )
        verification["precheck"] = precheck
        verification["execution_performed"] = True
        if not verification["healthy"]:
            verification["outcome"] = "POSTCHECK_FAILED"
            failed_checks = [
                check["name"]
                for check in verification["checks"]
                if not check["healthy"]
            ]
            return {
                "success": False,
                "execution_performed": True,
                **execution,
                "verification": verification,
                "error": (
                    "The action completed, but verification failed: "
                    + ", ".join(failed_checks)
                ),
            }

        verification["outcome"] = "RECOVERED"
        return {
            "success": True,
            "execution_performed": True,
            **execution,
            "verification": verification,
            "error": None,
        }
    except Exception as exc:
        LOGGER.exception("Registered action failed")
        return {
            "success": False,
            "execution_performed": execution_performed,
            **execution,
            "verification": None,
            "error": f"Executor error: {exc}",
        }
    finally:
        if client is not None:
            client.close()


def run_executor() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = ExecutorSettings.from_environment()
    database = RemediationDatabase(settings)
    active_action_rows = database.list_active_action_definitions()
    action_errors = validate_action_rows(active_action_rows)
    if action_errors:
        raise RuntimeError(
            "Invalid active action definition: " + "; ".join(action_errors)
        )

    active_action_ids = enabled_action_ids(active_action_rows)
    for row in active_action_rows:
        action = action_from_catalog_row(row)
        target = resolve_ssh_target(action.target_id, "EXECUTOR")
        LOGGER.info(
            "Resolved enabled action %s to target %s (%s)",
            action.action_id,
            target.target_id,
            target.hostname,
        )
    should_stop = False

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal should_stop
        should_stop = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    LOGGER.info("Remediation executor started as %s", settings.executor_id)
    LOGGER.info("Enabled registered actions: %s", active_action_ids)
    expired_count = database.expire_stale_approvals()
    if expired_count:
        LOGGER.warning(
            "Expired %s stale approved remediation request(s)",
            expired_count,
        )
    stale_count = database.move_stale_requests_to_manual_review()
    if stale_count:
        LOGGER.warning(
            "Moved %s stale RUNNING request(s) to MANUAL_REVIEW",
            stale_count,
        )
    next_stale_scan = time.monotonic() + 60

    while not should_stop:
        try:
            active_action_rows = database.list_active_action_definitions()
            action_errors = validate_action_rows(active_action_rows)
            if action_errors:
                raise RuntimeError(
                    "Invalid active action definition: "
                    + "; ".join(action_errors)
                )
            active_action_ids = enabled_action_ids(active_action_rows)
            database.heartbeat(active_action_ids)
            if time.monotonic() >= next_stale_scan:
                expired_count = database.expire_stale_approvals()
                if expired_count:
                    LOGGER.warning(
                        "Expired %s stale approved remediation request(s)",
                        expired_count,
                    )
                database.move_stale_requests_to_manual_review()
                next_stale_scan = time.monotonic() + 60
            request = database.claim_next_approved()
            if request is None:
                time.sleep(settings.poll_seconds)
                continue

            LOGGER.info(
                "Claimed remediation request %s",
                request["remediation_id"],
            )
            result = run_registered_action(request, settings, database)
            database.save_result(
                request["remediation_id"],
                request["execution_token"],
                result,
            )
            LOGGER.info(
                "Remediation %s finished: %s",
                request["remediation_id"],
                "SUCCEEDED" if result["success"] else "FAILED",
            )
        except Exception as exc:
            LOGGER.exception("Executor loop failure")
            try:
                database.heartbeat(active_action_ids, str(exc))
            except Exception:
                LOGGER.exception("Could not update executor heartbeat")
            time.sleep(settings.poll_seconds)

    LOGGER.info("Remediation executor stopped")


if __name__ == "__main__":
    run_executor()

# RCA_ADMIN_EXECUTION_MODE_V1
