"""Local tests: no database, production connection, kill or restart is used."""
import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "backend" / "app"
sys.path.insert(0, str(ROOT / "scripts"))
import install_executor_mode as installer
from schema_fixture import SOURCE

package = types.ModuleType("execution_test_app")
package.__path__ = [str(APP)]
sys.modules[package.__name__] = package
spec = importlib.util.spec_from_file_location("execution_test_app.managed_actions", APP / "managed_actions.py")
actions = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = actions
spec.loader.exec_module(actions)
lock_spec = importlib.util.spec_from_file_location("managed_executor_lock", APP / "managed_executor_lock.py")
locks = importlib.util.module_from_spec(lock_spec)
lock_spec.loader.exec_module(locks)
process_spec = importlib.util.spec_from_file_location("managed_process", APP / "managed_process.py")
process = importlib.util.module_from_spec(process_spec)
process_spec.loader.exec_module(process)

schema = types.ModuleType("execution_test_app.schemas")
sys.modules[schema.__name__] = schema
exec(compile(installer.patch_schemas(SOURCE), "patched_schemas.py", "exec"), schema.__dict__)


def definition(**updates):
    value = {"action_id": "restart_any_project", "display_name": "Restart worker",
             "operation": "RESTART_SCRIPT", "process_path": "/apps/example/worker.py",
             "command": "systemctl restart reviewed-worker"}
    return actions.ManagedActionInput.model_validate({**value, **updates})


class Cursor:
    def __init__(self, row=None):
        self.row = row
        self.calls = []
    def execute(self, sql, parameters=()):
        self.calls.append((sql, parameters))
    def fetchone(self):
        return self.row
    def close(self):
        pass


class ActionTests(unittest.TestCase):
    def test_catalog_uses_generic_fixed_v1_command(self):
        action = actions.compile_action(definition(), "new_dag", "new_server")
        self.assertEqual(action["component_id"], "new_dag")
        self.assertEqual(action["executor_type"], "SSH_COMMAND")
        self.assertTrue(action["requires_approval"])
        self.assertEqual(action["execution_spec"]["schema_version"], 1)
        self.assertEqual(action["execution_spec"]["prechecks"], action["execution_spec"]["postchecks"])
        self.assertLess(len(action["execution_spec"]["command"]), 16000)

    def test_versions_change_with_action_or_health_command(self):
        a = actions.compile_action(definition(), "dag", "server")
        b = actions.compile_action(definition(command="systemctl restart other-worker"), "dag", "server")
        self.assertNotEqual(a["implementation_version"], b["implementation_version"])

    def test_template_has_no_dag_specific_paths(self):
        for dag, path in [("new_pipeline", "/apps/new/main.py"), ("another_dag", "/other/script with spaces.py")]:
            action = actions.compile_action(definition(process_path=path), dag, "server")
            self.assertIn(dag, actions.render_action_sop(action))
            self.assertIn(path, action["execution_spec"]["command"])

    def test_unknown_fields_and_invalid_inputs_rejected(self):
        for change in [{"action_id": "Bad ID"}, {"process_path": "worker.py"},
                       {"python_executable": "python3; reboot"}, {"max_matches": 0},
                       {"signal": "SIGKILL"}, {"made_up": True}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                definition(**change)

    def test_custom_command_allows_reviewed_state_changes(self):
        for command in ["kill -TERM -- 12345", "systemctl restart another-service", "./restart.cmd"]:
            action = actions.compile_action(definition(operation="CUSTOM_COMMAND", command=command,
                health_command="printf OK", healthy_stdout_regex="OK", unhealthy_stdout_regex="DOWN"), "dag", "host")
            self.assertEqual(action["execution_spec"]["command"], command)

    def test_unknown_pid_placeholder_does_not_become_command(self):
        with self.assertRaises(ValueError):
            definition(operation="CUSTOM_COMMAND", command="kill {pid}", health_command="printf OK", healthy_stdout_regex="OK")

    def test_shell_resolved_pid_remains_fixed_reviewed_command(self):
        definition(operation="CUSTOM_COMMAND", command='pid=$(pgrep -f reviewed-worker); kill "$pid"',
                   health_command="printf OK", healthy_stdout_regex="OK")

    def test_state_change_is_not_accepted_as_health_check(self):
        with self.assertRaises(ValueError):
            definition(health_command="kill 123", healthy_stdout_regex="OK")

    def test_trim_does_not_claim_it_can_repair_zero(self):
        action = actions.compile_action(definition(operation="TRIM_PROCESSES"), "dag", "host")
        check = action["execution_spec"]["prechecks"][0]
        self.assertFalse(re.fullmatch(check["unhealthy_stdout_regex"], "0"))
        self.assertTrue(re.fullmatch(check["unhealthy_stdout_regex"], "2"))
        self.assertTrue(re.fullmatch(check["healthy_stdout_regex"], "1"))

    @unittest.skipUnless(os.name == "posix", "Linux process inventory diagnostic")
    def test_probe_is_read_only_and_does_not_match_its_own_arguments(self):
        value = definition(process_path="/this/does/not/exist/worker.py")
        result = subprocess.run(actions.process_probe(value), shell=True, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "0"))
        self.assertNotIn("os.kill", actions.process_probe(value))

    def test_generated_sop_only_contains_health_commands(self):
        action = actions.compile_action(definition(), "new_dag", "host")
        sop = actions.render_action_sop(action)
        self.assertIn("Run run_ssh_command on target 'host'", sop)
        self.assertIn("REMEDIATION_RECOMMENDED", sop)
        self.assertNotIn("systemctl restart reviewed-worker", sop)
        self.assertNotIn("classify the overall incident INCONCLUSIVE", sop)

    def test_no_automatic_registration_during_drafting(self):
        structured = types.SimpleNamespace(dag_id="new_dag", dag_source_code="",
            managed_action=definition(), selected_action_id=None, exception_types=["WorkerError"],
            target_registration=types.SimpleNamespace(model_dump=lambda **_: {"mode": "EXISTING", "target_id": "host"}))
        cursor = Cursor()
        @contextmanager
        def db():
            yield None, cursor
        model = types.SimpleNamespace(model_validate=lambda value: value)
        result = actions.managed_draft(types.SimpleNamespace(structured_input=structured), db, model)
        self.assertTrue(result["ready_for_review"])
        self.assertEqual(cursor.calls, [])
        self.assertTrue(result["action_preview"]["requires_approval"])


class ProcessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Linux process inventory diagnostic")
    def test_exact_argv_path_match_not_substring(self):
        with tempfile.TemporaryDirectory() as folder:
            config = {"process_path": "/apps/example/worker.py", "owner": ""}
            for pid, path in [(2001, "/apps/example/worker.py"), (2002, "/apps/example/worker.py.old")]:
                p = Path(folder, str(pid)); p.mkdir()
                (p / "cmdline").write_bytes(b"python\0" + path.encode() + b"\0")
                fields = ["S", "1"] + ["0"] * 17 + ["123"]
                (p / "stat").write_text(str(pid) + " (worker) " + " ".join(fields))
            rows = process.inventory(config, folder)
            self.assertEqual([row["pid"] for row in rows], [2001])

    def test_changed_pid_identity_aborts_before_signal(self):
        row = {"pid": 123456, "start": 1, "owner": "user", "argv": ["script"], "ppid": 1}
        with patch.object(process, "inventory", return_value=[{**row, "start": 2}]), \
             patch.object(process, "_ancestors", return_value=set()), \
             patch.object(process.os, "pidfd_open", return_value=99, create=True), \
             patch.object(process.signal, "pidfd_send_signal", create=True) as send, \
             patch.object(process.os, "close"):
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                process.terminate({"signal": "TERM"}, [row], 1)
            send.assert_not_called()

    def test_trim_keeps_oldest_and_restart_stops_before_start(self):
        rows = [{"pid": 10}, {"pid": 11}, {"pid": 12}]
        with patch.object(process, "inventory", return_value=rows), \
             patch.object(process, "terminate", return_value=[11, 12]) as stop:
            process.run({"operation": "TRIM_PROCESSES", "expected_count": 1,
                         "max_matches": 20, "signal": "TERM", "stop_timeout_seconds": 1})
            self.assertEqual(stop.call_args.args[1], rows[1:])

    def test_new_process_during_restart_prevents_second_start(self):
        with patch.object(process, "inventory", side_effect=[[], [{"pid": 88}]]), \
             patch.object(process, "terminate", return_value=[]), \
             patch("subprocess.run") as start:
            with self.assertRaisesRegex(RuntimeError, "appeared"):
                process.run({"operation": "RESTART_SCRIPT", "max_matches": 20, "signal": "TERM", "stop_timeout_seconds": 1})
            start.assert_not_called()


class ExecutorTests(unittest.TestCase):
    def test_uncertain_execution_requires_manual_review(self):
        for value in [{"success": False, "execution_performed": None},
                      {"success": False, "execution_performed": True, "timed_out": True},
                      {"success": False, "execution_performed": True, "verification": None}]:
            self.assertEqual(locks.final_result_status(value), "MANUAL_REVIEW")
        self.assertEqual(locks.final_result_status({"success": True}), "SUCCEEDED")
        self.assertEqual(locks.final_result_status({"success": False, "execution_performed": False}), "FAILED")

    def test_empty_or_truncated_output_cannot_trigger_action(self):
        check = types.SimpleNamespace(require_stdout=True, unhealthy_stdout_regex="0")
        for result in [{"state": "UNHEALTHY", "stdout": ""},
                       {"state": "HEALTHY", "stdout": "1", "output_truncated": True},
                       {"state": "UNHEALTHY", "stdout": "ERROR"}]:
            decorated = locks.validate_check_result(lambda *_: result.copy())
            self.assertEqual(decorated(None, check, 1000)["state"], "INCONCLUSIVE")

    def test_target_lock_busy_never_invokes_executor(self):
        cursor = Cursor((0,))
        connection = types.SimpleNamespace(cursor=lambda: cursor, close=lambda: None)
        db = types.SimpleNamespace(_connect=lambda: connection)
        called = []
        function = locks.with_target_lock(lambda *_: called.append(True))
        result = function({"target_id": "host"}, None, db)
        self.assertFalse(result["execution_performed"])
        self.assertEqual(called, [])

    def test_lock_released_after_action(self):
        cursor = Cursor((1,))
        connection = types.SimpleNamespace(cursor=lambda: cursor, close=lambda: None)
        result = locks.with_target_lock(lambda *_: {"success": True})(
            {"target_id": "host"}, None, types.SimpleNamespace(_connect=lambda: connection))
        self.assertTrue(result["success"])
        self.assertIn("RELEASE_LOCK", cursor.calls[-1][0])


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.input = schema.OnboardingStructuredInput.model_validate({
            "dag_id": "brand_new_pipeline", "exception_types": ["WorkerError"],
            "operating_mode": "APPROVAL_REQUIRED_ACTION", "investigation_read_only": True,
            "target_registration": {"mode": "EXISTING", "target_id": "server"},
            "managed_action": definition().model_dump(mode="json")})
        @contextmanager
        def db():
            yield None, Cursor()
        response = actions.managed_draft(types.SimpleNamespace(structured_input=self.input), db, schema.OnboardingAssistantResponse)
        self.request = schema.OnboardingActivationRequest(draft=response.draft, source_review=self.input,
                                                         action_definition_confirmed=True)

    def test_reviewed_input_roundtrips_through_pydantic(self):
        self.assertEqual(self.request.model_dump(mode="json")["action_legacy_field"], "unchanged")
        action = actions.validate_managed_activation(self.request, Cursor())
        self.assertEqual(action["component_id"], "brand_new_pipeline")

    def test_source_execution_mode_does_not_require_runtime_pid(self):
        value = self.input.model_copy(update={"dag_source_code": "kill_command = f'kill {pid}'"})
        validated = schema.OnboardingStructuredInput.model_validate(value.model_dump(mode="json"))
        self.assertEqual(validated.operating_mode, "APPROVAL_REQUIRED_ACTION")

    def test_confirmation_is_required(self):
        self.request.action_definition_confirmed = False
        with self.assertRaisesRegex(ValueError, "Confirm"):
            actions.register_managed_action(Cursor(), self.request, "admin")

    def test_tampered_command_sop_or_target_rejected_before_insert(self):
        for change in ["command", "sop", "target"]:
            request = self.request.model_copy(deep=True)
            if change == "command":
                request.draft.managed_action.command = "unreviewed-change"
            elif change == "sop":
                request.draft.dag.investigation_sop += " unreviewed"
            else:
                request.draft.target_registration.target_id = "other-server"
            cursor = Cursor()
            with self.subTest(change=change), self.assertRaises(ValueError):
                actions.register_managed_action(cursor, request, "admin")
            self.assertFalse(any("INSERT" in sql for sql, _ in cursor.calls))

    def test_catalog_insert_uses_actor_and_requires_approval(self):
        cursor = Cursor()
        actions.register_managed_action(cursor, self.request, "authenticated-admin")
        sql, parameters = cursor.calls[-1]
        self.assertIn("INSERT INTO remediation_action_catalog", sql)
        self.assertIn("TRUE", sql)
        self.assertEqual(parameters[-2:], ("authenticated-admin", "authenticated-admin"))
        self.assertIn('"schema_version":1', parameters[7])

    def test_action_id_collision_never_updates_catalog(self):
        cursor = Cursor({"action_id": "restart_any_project"})
        with self.assertRaisesRegex(ValueError, "already exists"):
            actions.register_managed_action(cursor, self.request, "admin")
        self.assertFalse(any("UPDATE" in sql[:6] or "INSERT" in sql[:6] for sql, _ in cursor.calls))

    def test_investigate_only_cannot_carry_action(self):
        payload = self.input.model_dump(mode="json")
        payload["operating_mode"] = "INVESTIGATE_ONLY"
        with self.assertRaises(ValueError):
            schema.OnboardingStructuredInput.model_validate(payload)

    def test_choose_new_or_existing_not_both(self):
        payload = self.input.model_dump(mode="json")
        payload["selected_action_id"] = "another_action"
        with self.assertRaises(ValueError):
            schema.OnboardingStructuredInput.model_validate(payload)

    def test_existing_action_must_match_component_and_server(self):
        action = actions.compile_action(definition(), "brand_new_pipeline", "server")
        value = self.input.model_copy(update={"managed_action": None, "selected_action_id": action["action_id"]})
        self.assertEqual(actions.action_for_input(value, Cursor(action))["action_id"], action["action_id"])
        with self.assertRaises(ValueError):
            actions.action_for_input(value, Cursor({**action, "target_id": "other"}))
        with self.assertRaises(ValueError):
            actions.action_for_input(value, Cursor({**action, "lifecycle_status": "DRAFT"}))

    def test_source_is_parsed_without_executing_it(self):
        value = self.input.model_copy(update={"dag_id": "", "dag_source_code": "raise RuntimeError('never run')\nDAG(dag_id='not_onboarded_before')"})
        action = actions.action_for_input(value)
        self.assertEqual(action["component_id"], "not_onboarded_before")

    def test_component_update_requires_explicit_flag(self):
        self.assertFalse(actions.prepare_component_update(Cursor(), self.request))

    def test_component_with_active_request_cannot_be_relinked(self):
        class ActiveCursor(Cursor):
            def fetchall(self):
                return [{"DAG_id": "brand_new_pipeline"}]
            def fetchone(self):
                return {"dag_id": "brand_new_pipeline"} if "registered_dags" in self.calls[-1][0] else {"remediation_id": 99}
        self.request.update_existing_component = True
        with self.assertRaisesRegex(ValueError, "active remediation"):
            actions.prepare_component_update(ActiveCursor(), self.request)


class ExtractedActionTests(unittest.TestCase):
    def candidate(self, path='/apps/project/worker.py', source=None):
        from test_action_candidates import WATCHDOG
        from execution_test_app.action_candidates import extract_action_candidates
        return extract_action_candidates(source or WATCHDOG, {'watchdog_path': json.dumps(path)})['candidates'][0]['prefill']

    def test_extracted_policy_survives_a_later_path_entry(self):
        value = self.candidate('worker.py')
        self.assertNotIn('health_command', value)
        value.update(process_path='/apps/project/worker.py', command='/apps/project/start.sh')
        result = actions.compile_action(value, 'new_dag', 'host')
        check = result['execution_spec']['prechecks'][0]
        self.assertIn('memory_percent', check['command'])
        self.assertIn('50', check['command'])
        self.assertEqual(check['unhealthy_stdout_regex'], 'ACTION_REQUIRED')

    def test_generated_health_check_follows_admin_scope_edits(self):
        import shlex
        value = self.candidate()
        value.update(process_path='/apps/edited/worker.py', owner='operator',
                     python_executable='/apps/monitor/python3', command='/apps/project/start.sh')
        result = actions.compile_action(value, 'new_dag', 'host')
        parts = shlex.split(result['execution_spec']['prechecks'][0]['command'])
        config = json.loads(parts[3])
        self.assertEqual(parts[0], '/apps/monitor/python3')
        self.assertEqual(config['path'], '/apps/edited/worker.py')
        self.assertEqual(config['owner'], 'operator')
        self.assertIn('memory_percent', json.dumps(config['predicates']))

    def test_untranslated_source_eligibility_is_not_silently_dropped(self):
        from test_action_candidates import WATCHDOG
        source = WATCHDOG.replace('if float(memory) >= RAM_threshold:', 'if float(memory) >= RAM_threshold and runtime_flag:')
        value = self.candidate(source=source)
        value['command'] = '/apps/project/start.sh'
        with self.assertRaisesRegex(ValueError, 'source conditions are unresolved'):
            actions.compile_action(value, 'new_dag', 'host')

    def test_extraction_response_uses_the_upgraded_request_contract(self):
        updated = types.ModuleType('execution_test_app.v2_schemas')
        updated.__package__ = 'execution_test_app'
        sys.modules[updated.__name__] = updated
        code = installer.upgrade_linked_schemas(installer.upgrade_schemas(installer.patch_schemas(SOURCE)))
        exec(compile(code, 'upgraded_schemas.py', 'exec'), updated.__dict__)
        payload = {'dag_id': 'another_dag', 'operating_mode': 'APPROVAL_REQUIRED_ACTION',
                   'dag_source_code': "client.exec_command('systemctl restart worker')",
                   'target_registration': {'mode': 'EXISTING', 'target_id': 'existing_server'},
                   'extract_action_candidates': True, 'investigation_read_only': False}
        request = updated.OnboardingAssistantRequest.model_validate({'structured_input': payload})
        response = actions.extraction_draft(request, updated.OnboardingAssistantResponse)
        self.assertFalse(response.ready_for_review)
        self.assertEqual(len(response.action_extraction['candidates']), 1)
        payload['extract_action_candidates'] = False
        with self.assertRaisesRegex(ValueError, 'read-only'):
            updated.OnboardingStructuredInput.model_validate(payload)

    def test_related_source_round_trip_prefills_a_compilable_approval_action(self):
        from test_action_candidates import WATCHDOG
        from test_linked_startup_sources import restart_source
        updated = types.ModuleType('execution_test_app.linked_schemas')
        updated.__package__ = 'execution_test_app'
        sys.modules[updated.__name__] = updated
        code = installer.upgrade_linked_schemas(installer.upgrade_schemas(installer.patch_schemas(SOURCE)))
        exec(compile(code, 'linked_schemas.py', 'exec'), updated.__dict__)
        request = updated.OnboardingAssistantRequest.model_validate({'structured_input': {
            'dag_id':'new_dag','operating_mode':'APPROVAL_REQUIRED_ACTION',
            'dag_source_code':WATCHDOG,'extract_action_candidates':True,
            'target_registration':{'mode':'EXISTING','target_id':'existing_server'},
            'airflow_variable_values':{'watchdog_path':'"worker.py"'},
            'related_dag_sources':{'execute_worker':restart_source()},
        }})
        response = actions.extraction_draft(request, updated.OnboardingAssistantResponse)
        prefill = response.action_extraction['candidates'][0]['prefill']
        self.assertEqual(prefill['process_path'],'/apps/project/worker.py')
        action = actions.compile_action(prefill,'new_dag','existing_server')
        self.assertTrue(action['requires_approval'])
        self.assertEqual(action['target_id'],'existing_server')
        self.assertIn('memory_percent',action['execution_spec']['prechecks'][0]['command'])
        self.assertIn('50',action['execution_spec']['prechecks'][0]['command'])
        self.assertEqual(request.model_dump()['structured_input']['related_dag_sources']['execute_worker'],restart_source().strip())

    def test_reported_airflow_template_dag_produces_a_compilable_action(self):
        from test_airflow_template_commands import SOURCE as STARTUP_SOURCE, MONITOR, VALUES, EXPECTED
        updated = types.ModuleType('execution_test_app.airflow_template_schemas')
        updated.__package__ = 'execution_test_app'
        sys.modules[updated.__name__] = updated
        code = installer.upgrade_linked_schemas(installer.upgrade_schemas(installer.patch_schemas(SOURCE)))
        exec(compile(code, 'template_schemas.py', 'exec'), updated.__dict__)
        request=updated.OnboardingAssistantRequest.model_validate({'structured_input':{
            'dag_id':'project_monitor','operating_mode':'APPROVAL_REQUIRED_ACTION',
            'dag_source_code':MONITOR,'extract_action_candidates':True,
            'target_registration':{'mode':'EXISTING','target_id':'selected_server'},
            'airflow_variable_values':VALUES,
            'related_dag_sources':{'flipchip_execute_linux_watchdog':STARTUP_SOURCE},
        }})
        response=actions.extraction_draft(request,updated.OnboardingAssistantResponse)
        candidate=response.action_extraction['candidates'][0]
        self.assertEqual(candidate['prefill']['command'],EXPECTED)
        self.assertEqual(candidate['prefill']['process_path'],'/test/project/worker.py')
        compiled=actions.compile_action(candidate['prefill'],'project_monitor','selected_server')
        self.assertTrue(compiled['requires_approval'])
        self.assertIn('memory_percent',compiled['execution_spec']['prechecks'][0]['command'])


if __name__ == "__main__":
    unittest.main()
