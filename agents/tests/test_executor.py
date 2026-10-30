import importlib.util
import importlib.machinery
import os
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch


if importlib.util.find_spec("dotenv") is None:
    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.__spec__ = importlib.machinery.ModuleSpec("dotenv", loader=None)
    dotenv_module.load_dotenv = lambda *_args, **_kwargs: None
    sys.modules["dotenv"] = dotenv_module

if importlib.util.find_spec("mysql") is None:
    mysql_module = types.ModuleType("mysql")
    connector_module = types.ModuleType("mysql.connector")
    mysql_module.__spec__ = importlib.machinery.ModuleSpec("mysql", loader=None)
    connector_module.__spec__ = importlib.machinery.ModuleSpec(
        "mysql.connector", loader=None
    )
    connector_module.connect = lambda **_kwargs: None
    mysql_module.connector = connector_module
    sys.modules["mysql"] = mysql_module
    sys.modules["mysql.connector"] = connector_module

if importlib.util.find_spec("paramiko") is None:
    paramiko_module = types.ModuleType("paramiko")
    paramiko_module.__spec__ = importlib.machinery.ModuleSpec("paramiko", loader=None)
    paramiko_module.SSHClient = object
    paramiko_module.RejectPolicy = object
    sys.modules["paramiko"] = paramiko_module

from agents.action_registry import ActionDefinition, CommandCheck, HttpCheck
from agents.config import ExecutorSettings
from agents.executor_old import (
    _http_command,
    run_registered_action,
    run_check,
    validate_request_definition,
)
from agents.action_registry import estimated_max_runtime_seconds


def settings() -> ExecutorSettings:
    return ExecutorSettings(
        db_host="db",
        db_port=3306,
        db_user="user",
        db_password="password",
        db_name="rca",
        poll_seconds=3,
        approval_ttl_seconds=900,
        lease_seconds=900,
        max_output_bytes=4096,
        executor_id="test:1",
    )


def action(*, enabled=True, version="v1") -> ActionDefinition:
    return ActionDefinition(
        action_id="restart_example",
        component_id="example",
        target_id="EXAMPLE01",
        implementation_version=version,
        command="/opt/example/restart.sh",
        verification_checks=(CommandCheck("process", "pgrep example"),),
        enabled=enabled,
    )


class ExecutorTests(unittest.TestCase):
    def test_runtime_estimate_covers_command_checks_and_retry_delays(self):
        definition = action()
        self.assertEqual(
            estimated_max_runtime_seconds(definition),
            60 + (7 * 15) + (5 * 5),
        )

    def test_http_check_extracts_status_and_requires_expected_code(self):
        check = HttpCheck("health", "http://127.0.0.1/healthz")
        command = _http_command(check)
        self.assertIn("curl --silent", command)
        self.assertIn("__RCA_HTTP_STATUS__", command)

        result = {
            "exit_code": 0,
            "stdout": "HTTP/1.1 200 OK\n\nhealthy\n__RCA_HTTP_STATUS__:200\n",
            "stderr": "",
            "timed_out": False,
            "output_truncated": False,
        }
        with patch("agents.executor.execute_fixed_command", return_value=result):
            checked = run_check(object(), check, settings().max_output_bytes)

        self.assertTrue(checked["healthy"])
        self.assertEqual(checked["state"], "HEALTHY")
        self.assertEqual(checked["status_code"], 200)

    def test_http_connection_refused_is_unhealthy(self):
        check = HttpCheck("health", "http://127.0.0.1/healthz")
        result = {
            "exit_code": 7,
            "stdout": "__RCA_HTTP_STATUS__:000\n",
            "stderr": "curl: failed to connect",
            "timed_out": False,
            "output_truncated": False,
        }
        with patch("agents.executor.execute_fixed_command", return_value=result):
            checked = run_check(object(), check, settings().max_output_bytes)

        self.assertFalse(checked["healthy"])
        self.assertEqual(checked["state"], "UNHEALTHY")

    def test_unexpected_diagnostic_error_is_inconclusive(self):
        check = CommandCheck("process", "pgrep example")
        result = {
            "exit_code": 127,
            "stdout": "",
            "stderr": "pgrep not found",
            "timed_out": False,
            "output_truncated": False,
        }
        with patch("agents.executor.execute_fixed_command", return_value=result):
            checked = run_check(object(), check, settings().max_output_bytes)

        self.assertFalse(checked["healthy"])
        self.assertEqual(checked["state"], "INCONCLUSIVE")

    def test_required_process_output_cannot_be_empty(self):
        check = CommandCheck(
            "process",
            "pgrep example",
            require_stdout=True,
        )
        result = {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "output_truncated": False,
        }
        with patch("agents.executor.execute_fixed_command", return_value=result):
            checked = run_check(object(), check, settings().max_output_bytes)

        self.assertFalse(checked["healthy"])
        self.assertEqual(checked["state"], "INCONCLUSIVE")

    def test_already_healthy_target_skips_action_command(self):
        request = {
            "action_id": "restart_example",
            "component_id_snapshot": "example",
            "target_id": "EXAMPLE01",
            "implementation_version_snapshot": "v1",
        }
        precheck = {
            "healthy": True,
            "state": "HEALTHY",
            "checked_at": "2026-09-14T00:00:00+00:00",
            "checks": [],
        }
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action()},
            clear=True,
        ), patch(
            "agents.executor.create_ssh_client",
            return_value=(
                SimpleNamespace(close=lambda: None),
                SimpleNamespace(hostname="example.internal"),
            ),
        ), patch(
            "agents.executor.check_current_state",
            return_value=precheck,
        ), patch(
            "agents.executor.execute_fixed_command"
        ) as execute:
            result = run_registered_action(request, settings())

        execute.assert_not_called()
        self.assertTrue(result["success"])
        self.assertFalse(result["execution_performed"])
        self.assertEqual(
            result["verification"]["outcome"],
            "ALREADY_HEALTHY",
        )

    def test_inconclusive_precheck_fails_without_execution(self):
        request = {
            "action_id": "restart_example",
            "component_id_snapshot": "example",
            "target_id": "EXAMPLE01",
            "implementation_version_snapshot": "v1",
        }
        precheck = {
            "healthy": False,
            "state": "INCONCLUSIVE",
            "checked_at": "2026-09-14T00:00:00+00:00",
            "checks": [],
        }
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action()},
            clear=True,
        ), patch(
            "agents.executor.create_ssh_client",
            return_value=(
                SimpleNamespace(close=lambda: None),
                SimpleNamespace(hostname="example.internal"),
            ),
        ), patch(
            "agents.executor.check_current_state",
            return_value=precheck,
        ), patch(
            "agents.executor.execute_fixed_command"
        ) as execute:
            result = run_registered_action(request, settings())

        execute.assert_not_called()
        self.assertFalse(result["success"])
        self.assertFalse(result["execution_performed"])
        self.assertEqual(
            result["verification"]["outcome"],
            "PRECHECK_INCONCLUSIVE",
        )

    def test_unhealthy_precheck_executes_then_requires_postcheck(self):
        request = {
            "action_id": "restart_example",
            "component_id_snapshot": "example",
            "target_id": "EXAMPLE01",
            "implementation_version_snapshot": "v1",
        }
        precheck = {
            "healthy": False,
            "state": "UNHEALTHY",
            "checked_at": "2026-09-14T00:00:00+00:00",
            "checks": [],
        }
        execution = {
            "exit_code": 0,
            "stdout": "restarted",
            "stderr": "",
            "timed_out": False,
            "output_truncated": False,
        }
        postcheck = {
            "healthy": True,
            "state": "HEALTHY",
            "attempts_used": 1,
            "checks": [],
        }
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action()},
            clear=True,
        ), patch(
            "agents.executor.create_ssh_client",
            return_value=(
                SimpleNamespace(close=lambda: None),
                SimpleNamespace(hostname="example.internal"),
            ),
        ), patch(
            "agents.executor.check_current_state",
            return_value=precheck,
        ), patch(
            "agents.executor.execute_fixed_command",
            return_value=execution,
        ) as execute, patch(
            "agents.executor.verify_action",
            return_value=postcheck,
        ):
            result = run_registered_action(request, settings())

        execute.assert_called_once()
        self.assertTrue(result["success"])
        self.assertTrue(result["execution_performed"])
        self.assertEqual(result["verification"]["outcome"], "RECOVERED")

    def test_disabled_action_is_rejected_before_ssh(self):
        request = {
            "action_id": "restart_example",
            "component_id_snapshot": "example",
            "target_id": "EXAMPLE01",
            "implementation_version_snapshot": "v1",
        }
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action(enabled=False)},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "disabled"):
                validate_request_definition(request)

    def test_target_or_version_mismatch_is_rejected(self):
        request = {
            "action_id": "restart_example",
            "component_id_snapshot": "example",
            "target_id": "WRONG",
            "implementation_version_snapshot": "v1",
        }
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action()},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "Target mismatch"):
                validate_request_definition(request)

        request["component_id_snapshot"] = "wrong_component"
        request["target_id"] = "EXAMPLE01"
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action()},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "Component mismatch"):
                validate_request_definition(request)

        request["component_id_snapshot"] = "example"
        request["target_id"] = "EXAMPLE01"
        request["implementation_version_snapshot"] = "old"
        with patch.dict(
            "agents.executor.ACTION_REGISTRY",
            {"restart_example": action(version="new")},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "changed after approval"):
                validate_request_definition(request)


if __name__ == "__main__":
    unittest.main()
