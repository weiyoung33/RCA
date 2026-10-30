import importlib.util
import os
import sys
import types
import unittest
from contextlib import contextmanager
from unittest.mock import patch

os.environ.setdefault("DB_HOST", "test-host")
os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault("DB_NAME", "test-database")

if importlib.util.find_spec("mysql") is None:
    mysql_module = types.ModuleType("mysql")
    connector_module = types.ModuleType("mysql.connector")
    pooling_module = types.ModuleType("mysql.connector.pooling")

    class DummyPool:
        def __init__(self, **_kwargs):
            pass

    pooling_module.MySQLConnectionPool = DummyPool
    connector_module.pooling = pooling_module
    mysql_module.connector = connector_module
    sys.modules["mysql"] = mysql_module
    sys.modules["mysql.connector"] = connector_module
    sys.modules["mysql.connector.pooling"] = pooling_module

if importlib.util.find_spec("dotenv") is None:
    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.load_dotenv = lambda: None
    sys.modules["dotenv"] = dotenv_module

from app.repository import (
    create_review,
    inject_test_incident,
    list_closed_reviews,
    promote_closed_review,
)


class FakeCursor:
    def __init__(self, pipeline_status="VERIFIED", update_count=1):
        self.pipeline_status = pipeline_status
        self.update_count = update_count
        self.lastrowid = 41
        self.rowcount = 0
        self.executions = []

    def execute(self, statement, parameters=None):
        self.executions.append((statement, parameters))
        if "UPDATE live_incidents" in statement:
            self.rowcount = self.update_count

    def fetchone(self):
        return {
            "pipeline_status": self.pipeline_status,
            "component_id": "example_dag",
            "exception_type": "ConnectionError",
        }


class ClosedReviewsCursor:
    def __init__(self):
        self.executions = []

    def execute(self, statement, parameters=None):
        self.executions.append((statement, parameters))

    def fetchall(self):
        return [
            {
                "review_id": 9,
                "incident_id": 24,
                "component_id": "example_dag",
                "selected_actions": '["Restart worker", "Verify endpoint"]',
                "promoted_to_knowledge_base": 1,
            }
        ]


class PromotionCursor:
    def __init__(self, promoted=False, decision="accepted"):
        self.promoted = promoted
        self.decision = decision
        self.rowcount = 0
        self.executions = []

    def execute(self, statement, parameters=None):
        self.executions.append((statement, parameters))
        if "UPDATE incident_reviews" in statement:
            self.rowcount = 1

    def fetchone(self):
        return {
            "review_id": 9,
            "decision": self.decision,
            "final_root_cause": "Confirmed network timeout",
            "selected_actions": '["Restore route", "Verify endpoint"]',
            "promoted_to_knowledge_base": self.promoted,
            "component_id": "example_dag",
            "exception_type": "ConnectionError",
            "pipeline_status": "CLOSED",
        }


class InjectionCursor:
    def __init__(self):
        self.lastrowid = 73
        self.executions = []

    def execute(self, statement, parameters=None):
        self.executions.append((statement, parameters))


def fake_database_cursor(cursor):
    @contextmanager
    def manager(commit=False):
        yield object(), cursor

    return manager


class ReviewTests(unittest.TestCase):
    def test_known_fixture_is_inserted_as_one_new_incident(self):
        cursor = InjectionCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            result = inject_test_incident("gunicorn_missing")

        self.assertEqual(result["incident_id"], 73)
        self.assertEqual(result["pipeline_status"], "NEW")
        self.assertEqual(len(cursor.executions), 1)
        self.assertIn("INSERT INTO live_incidents", cursor.executions[0][0])
        self.assertEqual(
            cursor.executions[0][1],
            (
                "airflow",
                "flipchip_monitor_flask_app_pll",
                "2026-09-07 16:20:00",
                "AirflowAlertException",
                "0 instances of gunicorn are running. Please check.",
                4,
                "NEW",
            ),
        )

    def test_unknown_fixture_is_not_inserted(self):
        cursor = InjectionCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            result = inject_test_incident("not_registered")

        self.assertIsNone(result)
        self.assertEqual(cursor.executions, [])

    def test_closed_review_can_be_promoted_once(self):
        cursor = PromotionCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            result = promote_closed_review(9, "Prototype Engineer")

        self.assertTrue(result["knowledge_base_promoted"])
        self.assertFalse(result["already_promoted"])
        self.assertEqual(len(cursor.executions), 3)
        self.assertIn("INSERT INTO rca_knowledge_base", cursor.executions[1][0])
        self.assertIn("UPDATE incident_reviews", cursor.executions[2][0])

    def test_already_promoted_review_does_not_create_duplicate_knowledge(self):
        cursor = PromotionCursor(promoted=True)
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            result = promote_closed_review(9, "Prototype Engineer")

        self.assertTrue(result["already_promoted"])
        self.assertEqual(len(cursor.executions), 1)

    def test_closed_review_archive_normalizes_database_values(self):
        cursor = ClosedReviewsCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            reviews = list_closed_reviews(limit=100, offset=0)

        self.assertEqual(cursor.executions[0][1], (100, 0))
        self.assertIn("WHERE i.pipeline_status = 'CLOSED'", cursor.executions[0][0])
        self.assertEqual(reviews[0]["selected_actions"], ["Restart worker", "Verify endpoint"])
        self.assertTrue(reviews[0]["promoted_to_knowledge_base"])

    def test_review_and_close_are_requested_in_one_database_context(self):
        cursor = FakeCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            result = create_review(
                incident_id=24,
                decision="accepted_with_edits",
                final_root_cause="Confirmed worker memory exhaustion",
                selected_actions=["Increase the worker memory limit"],
                comment="Validated after recovery",
                reviewer="Prototype Engineer",
            )

        self.assertEqual(result["review_id"], 41)
        self.assertEqual(result["pipeline_status"], "CLOSED")
        self.assertFalse(result["knowledge_base_promoted"])
        self.assertEqual(len(cursor.executions), 3)
        self.assertIn("INSERT INTO incident_reviews", cursor.executions[1][0])
        self.assertIn("SET pipeline_status = 'CLOSED'", cursor.executions[2][0])

    def test_approved_review_can_be_promoted(self):
        cursor = FakeCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            result = create_review(
                incident_id=24,
                decision="accepted",
                final_root_cause="Confirmed network timeout",
                selected_actions=["  Restore the network route  "],
                comment="Verified by the engineer",
                reviewer="Prototype Engineer",
                promote_to_knowledge_base=True,
            )

        self.assertTrue(result["knowledge_base_promoted"])
        self.assertEqual(len(cursor.executions), 5)
        self.assertIn("INSERT INTO rca_knowledge_base", cursor.executions[2][0])
        self.assertEqual(
            cursor.executions[2][1],
            (
                "example_dag",
                "ConnectionError",
                "Confirmed network timeout",
                "Restore the network route",
            ),
        )
        self.assertIn("UPDATE incident_reviews", cursor.executions[3][0])
        self.assertIn("SET pipeline_status = 'CLOSED'", cursor.executions[4][0])

    def test_rejected_review_cannot_be_promoted(self):
        cursor = FakeCursor()
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            with self.assertRaisesRegex(ValueError, "rejected resolution"):
                create_review(
                    24,
                    "rejected",
                    "Different cause",
                    ["Different action"],
                    "",
                    "Engineer",
                    True,
                )

        self.assertEqual(cursor.executions, [])

    def test_non_verified_incident_cannot_be_reviewed(self):
        cursor = FakeCursor(pipeline_status="ANALYZING")
        with patch("app.repository.database_cursor", fake_database_cursor(cursor)):
            with self.assertRaisesRegex(ValueError, "Only VERIFIED"):
                create_review(24, "accepted", "Cause", [], "", "Engineer")

        self.assertEqual(len(cursor.executions), 1)


if __name__ == "__main__":
    unittest.main()
