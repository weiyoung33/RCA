from __future__ import annotations

import unittest

from pydantic import ValidationError

from app.onboarding_agent import (
    _server_validation,
    request_contains_apparent_secret,
)
from app.schemas import (
    OnboardingAssistantRequest,
    OnboardingAssistantResponse,
)


def valid_response_payload() -> dict:
    return {
        "assistant_message": "The draft is ready for administrator review.",
        "ready_for_review": True,
        "missing_fields": [],
        "validation_issues": [],
        "draft": {
            "schema_version": 1,
            "lifecycle_status": "DRAFT",
            "dag": {
                "dag_id": "example_monitor",
                "exception_types": ["AirflowAlertException"],
                "investigation_sop": (
                    "Run the read-only process check and report the result."
                ),
            },
            "target_registration": {
                "mode": "EXISTING",
                "target_id": "EXAMPLE_TARGET",
            },
            "remediation_action": None,
            "review_template": {
                "summary": "Review the diagnostic-only monitor.",
                "sop_review_points": ["Confirm the SOP is read-only."],
                "action_review_points": [],
                "activation_requirements": [
                    "Test the draft before separate activation approval."
                ],
            },
        },
    }


class OnboardingSchemaTests(unittest.TestCase):
    def test_valid_draft_passes_strict_and_server_validation(self):
        response = OnboardingAssistantResponse.model_validate(
            valid_response_payload()
        )

        missing, issues = _server_validation(response.draft)

        self.assertEqual(missing, [])
        self.assertEqual(issues, [])

    def test_unexpected_llm_field_is_rejected(self):
        payload = valid_response_payload()
        payload["unexpected"] = "not permitted"

        with self.assertRaises(ValidationError):
            OnboardingAssistantResponse.model_validate(payload)

    def test_non_draft_lifecycle_is_rejected(self):
        payload = valid_response_payload()
        payload["draft"]["lifecycle_status"] = "ACTIVE"

        with self.assertRaises(ValidationError):
            OnboardingAssistantResponse.model_validate(payload)

    def test_apparent_secret_is_rejected_before_llm_call(self):
        request = OnboardingAssistantRequest(
            message="Use password=do-not-send for this target",
        )

        self.assertTrue(request_contains_apparent_secret(request))

    def test_state_changing_precheck_is_not_review_ready(self):
        payload = valid_response_payload()
        payload["draft"]["remediation_action"] = {
            "action_id": "restart_example",
            "component_id": "example_monitor",
            "target_id": "EXAMPLE_TARGET",
            "display_name": "Restart example",
            "description": "Restart the example service.",
            "risk_level": "MEDIUM",
            "lifecycle_status": "DRAFT",
            "implementation_version": "1.0.0",
            "executor_type": "SSH_COMMAND",
            "execution_spec": {
                "schema_version": 1,
                "command": "systemctl restart example",
                "command_timeout_seconds": 60,
                "prechecks": [
                    {
                        "kind": "command",
                        "name": "bad_precheck",
                        "command": "systemctl restart example",
                        "expected_exit_codes": [0],
                        "unhealthy_exit_codes": [1],
                        "timeout_seconds": 15,
                        "require_stdout": False,
                        "healthy_stdout_regex": None,
                        "unhealthy_stdout_regex": None,
                    }
                ],
                "postchecks": [
                    {
                        "kind": "command",
                        "name": "process_check",
                        "command": "pgrep -c example",
                        "expected_exit_codes": [0],
                        "unhealthy_exit_codes": [1],
                        "timeout_seconds": 15,
                        "require_stdout": True,
                        "healthy_stdout_regex": "^[1-9][0-9]*$",
                        "unhealthy_stdout_regex": "^0$",
                    }
                ],
                "verification_attempts": 6,
                "verification_delay_seconds": 5,
            },
            "verification_summary": "The process must be running.",
            "rollback_summary": None,
            "requires_approval": True,
        }
        payload["draft"]["review_template"]["action_review_points"] = [
            "Review the exact action and checks."
        ]
        response = OnboardingAssistantResponse.model_validate(payload)

        _, issues = _server_validation(response.draft)

        self.assertIn(
            "draft.remediation_action.execution_spec.prechecks[0].command "
            "must be diagnostic-only",
            issues,
        )


if __name__ == "__main__":
    unittest.main()
