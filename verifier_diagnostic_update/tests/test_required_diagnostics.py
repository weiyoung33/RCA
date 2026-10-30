"""Offline scheduling tests. No SSH, MySQL, HTTP or model service is contacted.

Run from the application root after extracting the update:
    python -m unittest discover -s verifier_diagnostic_update/tests -v
VERIFIER_TEST_SOURCE can optionally select an existing structured Verifier file.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("diagnostic_installer", PACKAGE / "scripts/install_required_diagnostics.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
HELPER = (PACKAGE / "patches/required_diagnostics.py").read_text(encoding="utf-8")
SOURCE_PATH = Path(os.environ.get("VERIFIER_TEST_SOURCE", str(PACKAGE.parent / "agents/verifier_agent.py")))
SOURCE = SOURCE_PATH.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
PATCHED = installer.patch_source(SOURCE, HELPER)


def load_verifier():
    def unavailable(*args, **kwargs):
        raise AssertionError("Unexpected external access in offline test")
    stubs = {name: types.ModuleType(name) for name in (
        "mysql", "mysql.connector", "paramiko", "requests", "dotenv", "target_registry")}
    stubs["mysql"].connector = stubs["mysql.connector"]
    stubs["mysql.connector"].connect = unavailable
    stubs["paramiko"].SSHClient = unavailable
    for name in ("AuthenticationException", "SSHException"):
        setattr(stubs["paramiko"], name, type(name, (Exception,), {}))
    request_error = type("RequestException", (Exception,), {})
    stubs["requests"].RequestException = request_error
    for name in ("Timeout", "ConnectionError", "HTTPError"):
        setattr(stubs["requests"], name, type(name, (request_error,), {}))
    stubs["requests"].get = stubs["requests"].post = unavailable
    stubs["dotenv"].load_dotenv = lambda **kwargs: None
    stubs["target_registry"].TargetConfigurationError = type("TargetConfigurationError", (Exception,), {})
    for name in ("install_pinned_host_key", "resolve_database_target", "resolve_ssh_target"):
        setattr(stubs["target_registry"], name, unavailable)
    module = types.ModuleType("verifier_diagnostic_under_test")
    module.__file__ = str(SOURCE_PATH)
    with patch.dict(sys.modules, stubs):
        exec(compile(PATCHED, str(SOURCE_PATH), "exec"), module.__dict__)
    return module


v = load_verifier()
GOOD = {"status": "SUCCESS", "summary": "read-only check completed", "output": "1"}


def sql_step(number, query="SELECT COUNT(*) FROM t_events", target="EVENT_DB"):
    return (str(number) + ". Run query_database on target '" + target
            + "' with this exact read-only query:\n\n```sql\n" + query + "\n```\n\n")


def ssh_step(number, command="pgrep -c -f -- '[m]ain.py'", target="APP_SSH"):
    return (str(number) + ". Run run_ssh_command on target '" + target
            + "' with this exact command:\n\n```sh\n" + command + "\n```\n\n")


def final(ids=(1,), classification="NO_REMEDIATION_REQUIRED"):
    return {"is_final": True, "classification": classification,
            "finding": "Current results meet the supplied SOP branch.",
            "sop_branch": "The current count meets the expected branch.",
            "recommended_action": "", "confidence_score": 91,
            "diagnostic_findings": [{"kind": "INTERPRETATION", "statement": "Current measurements assessed.",
                                     "evidence_step_ids": list(ids)}],
            "error_group_findings": [], "unresolved_questions": []}


def entry(check, step=1, result=None):
    return {"step": step, **check, "result": copy.deepcopy(GOOD if result is None else result)}


class ParserTests(unittest.TestCase):
    def test_three_required_queries_all_resolve(self):
        sop = sql_step(1) + sql_step(2, "SELECT id FROM t_events ORDER BY id") + sql_step(3, "SELECT NOW()")
        self.assertEqual(len(v._rca_diag_initial_checks(sop)), 3)

    def test_inline_original_database_sop(self):
        sop = "1. Run the query_database tool. Set the target to 'FLIPCHIP_DB' and use the exact query: 'SELECT source, file_name, error_message FROM t_monitor_flipchip_errors WHERE error_timestamp >= NOW() - INTERVAL 1 HOUR ORDER BY error_timestamp DESC LIMIT 5;'\n2. Evaluate the output."
        checks = v._rca_diag_initial_checks(sop)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["target"], "FLIPCHIP_DB")
        self.assertTrue(checks[0]["query"].endswith("LIMIT 5;"))

    def test_unquoted_hostname_and_bare_command(self):
        sop = "1. Run run_ssh_command on app.example.test with this exact command:\n\npgrep -f --count main.py\n\nUse the integer.\n2. Interpret the output."
        self.assertEqual(v._rca_diag_initial_checks(sop)[0]["target"], "app.example.test")

    def test_bare_multiline_sql(self):
        sop = "1. Run query_database on target 'DB' with the exact query:\n\nSELECT id, name\nFROM events\nORDER BY id\n\n2. Interpret."
        self.assertEqual(v._rca_diag_initial_checks(sop)[0]["query"], "SELECT id, name\nFROM events\nORDER BY id")

    def test_markdown_tool_and_target(self):
        sop = "1. **Run** `run_ssh_command` on target `APP` with this exact command:\n\n```sh\npgrep -c main.py\n```\n"
        self.assertEqual(v._rca_diag_initial_checks(sop)[0]["target"], "APP")

    def test_http_and_ssh_mixed(self):
        sop = ssh_step(1) + "2. Run check_http_endpoint on http://10.1.2.3:5000/.\n\n3. Interpret the results."
        checks = v._rca_diag_initial_checks(sop)
        self.assertEqual([c["tool"] for c in checks], ["run_ssh_command", "check_http_endpoint"])
        self.assertEqual(checks[1]["target"], "http://10.1.2.3:5000/")

    def test_markdown_url(self):
        sop = "1. Run check_http_endpoint on [http://app:5000/](http://app:5000/)."
        self.assertEqual(v._rca_diag_initial_checks(sop)[0]["target"], "http://app:5000/")

    def test_network_port_requires_explicit_valid_port(self):
        self.assertEqual(v._rca_diag_initial_checks("1. Run check_port on app port 22.")[0]["port"], 22)
        for port in ("", " port 99999", " port 0"):
            self.assertEqual(v._rca_diag_initial_checks("1. Run check_port on app" + port), [])

    def test_conditional_http_is_not_preexecuted(self):
        sop = ssh_step(1) + "2. If exactly two processes exist, run check_http_endpoint on http://app/."
        self.assertEqual(len(v._rca_diag_initial_checks(sop)), 1)

    def test_optional_check_not_required(self):
        sop = ssh_step(1) + "2. Optional supporting observation: Run run_ssh_command on target 'APP_SSH' with this exact command:\n\n```sh\npgrep -af main.py\n```"
        self.assertEqual(len(v._rca_diag_initial_checks(sop)), 1)

    def test_condition_between_numbered_checks_stops_bootstrap(self):
        sop = sql_step(1) + "Run step 2 only if count returned by step 1 > 0. Otherwise skip.\n\n" + sql_step(2)
        self.assertEqual(len(v._rca_diag_initial_checks(sop)), 1)

    def test_condition_after_target_not_ignored(self):
        self.assertEqual(v._rca_diag_initial_checks("1. Run check_http_endpoint on http://app/ only if the process exists."), [])

    def test_explicit_initial_precondition_left_with_model(self):
        sop = "Run step 1 only if the production flag is enabled.\n\n" + sql_step(1)
        self.assertEqual(v._rca_diag_initial_checks(sop), [])

    def test_interpretation_step_stops_initial_sequence(self):
        sop = sql_step(1) + "2. Evaluate the database output.\n\n" + ssh_step(3)
        self.assertEqual(len(v._rca_diag_initial_checks(sop)), 1)

    def test_quoted_sql_literals_preserved(self):
        q = "SELECT IF(age > 15, 'FAIL', 'PASS') FROM measurements"
        self.assertEqual(v._rca_diag_initial_checks(sql_step(1, q))[0]["query"], q)

    def test_sentence_period_outside_inline_query_not_in_sql(self):
        sop = "1. Run query_database on target 'DB' with this exact query: 'SELECT count(*) FROM events;'.\n"
        self.assertEqual(v._rca_diag_initial_checks(sop)[0]["query"], "SELECT count(*) FROM events;")

    def test_numbered_lines_in_command_not_steps(self):
        sop = ssh_step(1, "printf 'hello\\n'\n1. command text") + sql_step(2)
        self.assertEqual(len(v._rca_diag_sections(sop)), 2)

    def test_missing_command_never_invented(self):
        self.assertEqual(v._rca_diag_initial_checks("1. Run run_ssh_command on target 'APP' with this exact command:"), [])

    def test_state_changes_remain_ineligible(self):
        for sop in (ssh_step(1, "kill 1234"), sql_step(1, "DELETE FROM events")):
            self.assertEqual(v._rca_diag_initial_checks(sop), [])

    def test_ml_limit_instruction_keeps_following_query(self):
        sop = sql_step(1) + sql_step(2) + "Before using this result, retain only the first (the number of returned rows from step 1 + 1) rows. Require a complete result.\n\n" + sql_step(3)
        self.assertEqual(len(v._rca_diag_initial_checks(sop)), 3)

    def test_different_unseen_names_no_dag_patterns(self):
        sop = sql_step(1, "SELECT AVG(metric) FROM arbitrary_source", "NEW_PRODUCT_DB")
        self.assertEqual(v._rca_diag_initial_checks(sop)[0]["target"], "NEW_PRODUCT_DB")


class FlowTests(unittest.TestCase):
    def run_agent(self, sop, responses, results=None, initial=None):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(v, "_call_llm", side_effect=responses) as model, patch.object(
            v, "_execute_tool", side_effect=results if results is not None else lambda *a: copy.deepcopy(GOOD)
        ) as execute:
            answer = v.run_verifier_with_findings("alert", "untrusted proposal", "untrusted fix", sop, initial)
        return answer, model, execute

    def test_three_sql_checks_before_one_final_model_call(self):
        sop = sql_step(1) + sql_step(2, "SELECT id FROM events") + sql_step(3, "SELECT NOW()")
        answer, model, execute = self.run_agent(sop, [final((1, 2, 3))])
        self.assertEqual(execute.call_count, 3)
        self.assertEqual(model.call_count, 1)
        self.assertEqual(answer["classification"], "NO_REMEDIATION_REQUIRED")
        self.assertEqual([e["step"] for e in answer["tool_history"]], [1, 2, 3])
        self.assertNotIn("untrusted proposal", model.call_args.args[0])

    def test_three_ssh_checks_before_final(self):
        sop = "".join(ssh_step(i, "pgrep -c -f script" + str(i)) for i in range(1, 4))
        answer, model, execute = self.run_agent(sop, [final((1, 2, 3))])
        self.assertEqual(execute.call_count, 3)
        self.assertEqual(answer["classification"], "NO_REMEDIATION_REQUIRED")

    def test_premature_answer_repaired_locally_for_unknown_layout(self):
        # This layout deliberately stays with the model instead of the parser.
        sop = "1. Run query_database using target 'DB': SELECT COUNT(*) FROM events\n"
        decision = {"is_final": False, "tool": "query_database", "target": "DB", "query": "SELECT COUNT(*) FROM events"}
        answer, model, execute = self.run_agent(sop, [final(), decision, final()])
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(model.call_count, 3)
        self.assertIn("DIAGNOSTIC SELECTION CORRECTION", model.call_args_list[1].args[0])
        self.assertEqual(len(answer["tool_history"]), 1)

    def test_repeated_premature_final_does_not_raise_transient_retry(self):
        sop = "1. Run query_database using target 'DB': SELECT id FROM events\n"
        answer, model, execute = self.run_agent(sop, [final(), final(), final()])
        self.assertEqual(model.call_count, 3)
        execute.assert_not_called()
        self.assertEqual(answer["classification"], "INCONCLUSIVE")
        self.assertFalse(answer["evidence_complete"])
        self.assertIn("two in-attempt corrections", " ".join(answer["unresolved_questions"]))

    def test_empty_tool_is_corrected_without_fake_history_step(self):
        bad = {"is_final": False, "tool": "", "target": ""}
        decision = {"is_final": False, "tool": "query_database", "target": "DB", "query": "SELECT id FROM events"}
        answer, model, execute = self.run_agent("1. Run query_database using target 'DB': SELECT id FROM events\n", [bad, decision, final()])
        self.assertEqual(len(answer["tool_history"]), 1)
        self.assertEqual(answer["tool_history"][0]["tool"], "query_database")

    def test_repair_budget_shared_across_steps(self):
        state = {"used": 2}
        with patch.object(v, "_call_llm", return_value=final()), self.assertRaises(v._RcaDiagnosticSelectionError):
            v._rca_diag_next_instruction("alert", "1. Run query_database using DB", [], [], state)

    def test_resume_completed_queries_without_reexecution(self):
        sop = sql_step(1) + sql_step(2, "SELECT NOW()")
        checks = v._rca_diag_initial_checks(sop)
        prior = [entry(checks[0])]
        answer, model, execute = self.run_agent(sop, [final((1, 2))], initial=prior)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(execute.call_args.args[0]["query"], "SELECT NOW()")
        self.assertEqual(len(answer["tool_history"]), 2)

    def test_full_retry_checkpoint_is_reused(self):
        sop = sql_step(1)
        prior = [entry(v._rca_diag_initial_checks(sop)[0])]
        answer, model, execute = self.run_agent(sop, [final()], initial=prior)
        execute.assert_not_called()
        self.assertEqual(answer["classification"], "NO_REMEDIATION_REQUIRED")

    def test_conflicting_checkpoint_is_not_silently_discarded(self):
        sop = sql_step(1)
        prior = [entry({"tool": "query_database", "target": "WRONG", "query": "SELECT 1"})]
        answer, model, execute = self.run_agent(sop, [], initial=prior)
        execute.assert_not_called()
        model.assert_not_called()
        self.assertIn("Saved diagnostic history", " ".join(answer["unresolved_questions"]))

    def test_network_model_timeout_preserves_tools_for_existing_retry(self):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(v, "_execute_tool", return_value=GOOD), patch.object(
            v, "_call_llm", side_effect=v.TransientVerifierLLMError("model timeout")
        ), self.assertRaises(v.TransientVerifierLLMError) as caught:
            v.run_verifier_with_findings("alert", "", "", sql_step(1))
        self.assertEqual(len(caught.exception.tool_history), 1)
        self.assertEqual(caught.exception.incident_evidence_sha256, v._evidence_hash("alert"))

    def test_failed_diagnostic_not_retried_just_to_satisfy_guard(self):
        failure = {"status": "AUTH_FAILURE", "summary": "credentials rejected"}
        answer, model, execute = self.run_agent(sql_step(1), [final(classification="INCONCLUSIVE")], [failure])
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(model.call_count, 1)
        self.assertEqual(answer["classification"], "INCONCLUSIVE")

    def test_failure_stops_bootstrap_and_retains_model_fallback(self):
        sop = ssh_step(1) + sql_step(2) + "On SSH failure, run verify_ip_reachability on APP_SSH."
        failure = {"status": "SSH_FAILURE", "summary": "SSH session unavailable"}
        decision = {"is_final": False, "tool": "verify_ip_reachability", "target": "APP_SSH"}
        answer, model, execute = self.run_agent(sop, [decision, final((1, 2), "INCONCLUSIVE")], [failure, GOOD])
        self.assertEqual([c.args[0]["tool"] for c in execute.call_args_list], ["run_ssh_command", "verify_ip_reachability"])
        self.assertEqual(answer["classification"], "INCONCLUSIVE")

    def test_conditional_detail_query_not_run_for_zero_branch(self):
        sop = sql_step(1) + "Run step 2 only if count > 0. Otherwise skip.\n\n" + sql_step(2, "SELECT message FROM events")
        answer, model, execute = self.run_agent(sop, [final()])
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(answer["classification"], "NO_REMEDIATION_REQUIRED")

    def test_conditional_detail_query_runs_when_model_selects_it(self):
        sop = sql_step(1) + "Run step 2 only if count > 0. Otherwise skip.\n\n" + sql_step(2, "SELECT message FROM events")
        decision = {"is_final": False, "tool": "query_database", "target": "EVENT_DB", "query": "SELECT message FROM events"}
        answer, model, execute = self.run_agent(sop, [decision, final((1, 2), "MANUAL_REVIEW_REQUIRED")])
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(answer["classification"], "MANUAL_REVIEW_REQUIRED")

    def test_actual_tool_limit_not_spent_on_invalid_decisions(self):
        sop = "1. Run query_database using target 'DB': SELECT id FROM events\n"
        decision = {"is_final": False, "tool": "query_database", "target": "DB", "query": "SELECT id FROM events"}
        with patch.object(v, "MAX_TOOL_STEPS", 1):
            answer, model, execute = self.run_agent(sop, [final(), decision, final()])
        self.assertEqual(len(answer["tool_history"]), 1)
        self.assertEqual(model.call_count, 3)

    def test_too_many_required_checks_reports_specific_limit(self):
        sop = sql_step(1) + sql_step(2)
        with patch.object(v, "MAX_TOOL_STEPS", 1):
            answer, model, execute = self.run_agent(sop, [])
        execute.assert_not_called()
        self.assertIn("VERIFIER_MAX_TOOL_STEPS", " ".join(answer["unresolved_questions"]))

    def test_missing_prefix_cannot_report_healthy(self):
        checks = v._rca_diag_initial_checks(sql_step(1) + sql_step(2))
        guarded = v._rca_diag_guard_final(final(), [entry(checks[0])], checks)
        self.assertEqual(guarded["classification"], "INCONCLUSIVE")
        self.assertEqual(guarded["recommended_action"], "")

    def test_observed_abnormal_manual_review_keeps_missing_checks_visible(self):
        checks = v._rca_diag_initial_checks(sql_step(1) + sql_step(2) + sql_step(3))
        prior = [entry(checks[0]), entry(checks[1], 2, {"status": "AUTH_FAILURE", "summary": "Query unavailable"})]
        guarded = v._rca_diag_guard_final(final((1,), "MANUAL_REVIEW_REQUIRED"), prior, checks)
        self.assertEqual(guarded["classification"], "MANUAL_REVIEW_REQUIRED")
        self.assertIn("Not every initial", " ".join(guarded["unresolved_questions"]))

    def test_existing_tool_gates_still_block_unapproved_operations(self):
        with patch.object(v, "run_ssh_command") as ssh, patch.object(v, "query_database") as query:
            ssh_result = v._execute_tool({"tool": "run_ssh_command", "target": "APP_SSH", "command": "kill 1234"}, ssh_step(1))
            sql_result = v._execute_tool({"tool": "query_database", "target": "EVENT_DB", "query": "DELETE FROM events"}, sql_step(1))
            wrong_target = v._execute_tool({"tool": "query_database", "target": "OTHER_DB", "query": "SELECT id FROM events"}, sql_step(1))
        for result in (ssh_result, sql_result, wrong_target):
            self.assertEqual(result["status"], "BLOCKED")
        ssh.assert_not_called()
        query.assert_not_called()

    def test_limited_coverage_marker_still_forces_inconclusive(self):
        if "RCA_LIMITED_COVERAGE_V1:" not in SOURCE:
            self.skipTest("This older source does not contain the optional limited-coverage guard.")
        answer, model, execute = self.run_agent(sql_step(1) + "<!-- RCA_LIMITED_COVERAGE_V1:abc -->", [final()])
        self.assertEqual(answer["classification"], "INCONCLUSIVE")


class InstallerTests(unittest.TestCase):
    def test_python39_grammar(self):
        ast.parse(PATCHED, feature_version=(3, 9))
        ast.parse(HELPER, feature_version=(3, 9))

    def test_idempotent(self):
        self.assertEqual(installer.patch_source(PATCHED, HELPER), PATCHED)

    def test_tools_and_configuration_functions_unchanged(self):
        def functions(source):
            return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(source).body
                    if isinstance(n, ast.FunctionDef)}
        before, after = functions(SOURCE), functions(PATCHED)
        for name in before:
            if name != "run_verifier_with_findings":
                self.assertEqual(before[name], after[name], name)

    def test_incompatible_flow_refused(self):
        if installer.MARKER not in SOURCE:
            bad = SOURCE.replace("for step in range(", "for other_step in range(", 1)
            with self.assertRaises(ValueError):
                installer.patch_source(bad, HELPER)

    def test_partial_install_refused(self):
        bad = PATCHED.replace("required_checks = _rca_diag_bootstrap", "required_checks = other_function", 1)
        with self.assertRaises(ValueError):
            installer.patch_source(bad, HELPER)

    def test_preview_and_atomic_apply_preserve_newlines_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verifier_agent.py"
            original = b"\xef\xbb\xbf" + SOURCE.replace("\n", "\r\n").encode()
            path.write_bytes(original)
            with contextlib.redirect_stdout(io.StringIO()):
                installer.install(path, False)
            self.assertEqual(path.read_bytes(), original)
            with contextlib.redirect_stdout(io.StringIO()):
                installer.install(path, True)
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\n", path.read_bytes().replace(b"\r\n", b""))
            if installer.MARKER not in SOURCE:
                backup = list(Path(directory).glob("*.bak"))
                self.assertEqual(len(backup), 1)
                self.assertEqual(backup[0].read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
