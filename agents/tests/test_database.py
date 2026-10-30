from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
import unittest
from contextlib import contextmanager
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

from agents.database_old import RemediationDatabase


class FakeCursor:
    def __init__(self, *, rows=None, row=None):
        self.rows = rows or []
        self.row = row
        self.rowcount = 1
        self.calls = []

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.row


def settings():
    return SimpleNamespace(
        approval_ttl_seconds=900,
        lease_seconds=900,
        executor_id="executor:test",
    )


class RemediationDatabaseTests(unittest.TestCase):
    def test_expired_approval_is_failed_with_audit_event(self):
        database = RemediationDatabase(settings())
        cursor = FakeCursor(rows=[{"remediation_id": 7}])

        @contextmanager
        def fake_cursor(*, commit=False):
            self.assertTrue(commit)
            yield object(), cursor

        with patch.object(database, "_cursor", fake_cursor):
            expired = database.expire_stale_approvals()

        self.assertEqual(expired, 1)
        statements = "\n".join(call[0] for call in cursor.calls)
        self.assertIn("SET status = 'FAILED'", statements)
        self.assertIn("INSERT INTO remediation_events", statements)

    def test_claim_filters_expired_approvals_without_skip_locked(self):
        database = RemediationDatabase(settings())
        cursor = FakeCursor(
            row={
                "remediation_id": 9,
                "incident_id": 3,
                "component_id_snapshot": "example",
                "action_id": "restart_example",
                "target_id": "EXAMPLE01",
                "implementation_version_snapshot": "v1",
            }
        )

        @contextmanager
        def fake_cursor(*, commit=False):
            self.assertTrue(commit)
            yield object(), cursor

        with patch.object(database, "_cursor", fake_cursor):
            request = database.claim_next_approved()

        self.assertIsNotNone(request)
        self.assertIn("execution_token", request)
        statements = "\n".join(call[0] for call in cursor.calls)
        self.assertIn("approved_at >= TIMESTAMPADD", statements)
        self.assertNotIn("SKIP LOCKED", statements)


if __name__ == "__main__":
    unittest.main()
