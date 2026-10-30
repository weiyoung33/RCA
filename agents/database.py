from __future__ import annotations

from .managed_executor_lock import final_result_status

import json
import os
import socket
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

import mysql.connector

from .config import ExecutorSettings


class RemediationDatabase:
    def __init__(self, settings: ExecutorSettings):
        self.settings = settings

    def _connect(self):
        return mysql.connector.connect(
            host=self.settings.db_host,
            port=self.settings.db_port,
            user=self.settings.db_user,
            password=self.settings.db_password,
            database=self.settings.db_name,
            connection_timeout=5,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            use_unicode=True,
            use_pure=True,
        )

    @contextmanager
    def _cursor(self, *, commit: bool = False) -> Iterator[tuple[Any, Any]]:
        connection = self._connect()
        cursor = connection.cursor(dictionary=True)
        try:
            yield connection, cursor
            if commit:
                connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def _insert_event(
        cursor: Any,
        remediation_id: int,
        from_status: Optional[str],
        to_status: str,
        actor_name: str,
        message: str,
        evidence: Optional[dict[str, Any]] = None,
    ) -> None:
        cursor.execute(
            """
            INSERT INTO remediation_events (
                remediation_id, from_status, to_status,
                actor_type, actor_name, message, evidence
            ) VALUES (%s, %s, %s, 'EXECUTOR', %s, %s, %s)
            """,
            (
                remediation_id,
                from_status,
                to_status,
                actor_name,
                message,
                json.dumps(evidence, ensure_ascii=False) if evidence else None,
            ),
        )

    def heartbeat(
        self,
        enabled_actions: list[str],
        last_error: Optional[str] = None,
    ) -> None:
        with self._cursor(commit=True) as (_, cursor):
            cursor.execute(
                """
                INSERT INTO remediation_executor_heartbeats (
                    executor_id, hostname, process_id,
                    registry_actions, last_error
                ) VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    hostname = VALUES(hostname),
                    process_id = VALUES(process_id),
                    registry_actions = VALUES(registry_actions),
                    last_error = VALUES(last_error),
                    last_seen_at = CURRENT_TIMESTAMP
                """,
                (
                    self.settings.executor_id,
                    socket.gethostname(),
                    os.getpid(),
                    json.dumps(enabled_actions),
                    last_error,
                ),
            )

    def list_active_action_definitions(self) -> list[dict[str, Any]]:
        """Load active database actions for validation and executor reporting."""

        with self._cursor() as (_, cursor):
            cursor.execute(
                """
                SELECT
                    action_id,
                    component_id,
                    target_id,
                    implementation_version,
                    executor_type,
                    execution_spec
                FROM remediation_action_catalog
                WHERE lifecycle_status = 'ACTIVE'
                ORDER BY action_id
                """
            )
            return cursor.fetchall()

    def move_stale_requests_to_manual_review(self) -> int:
        """Never replay an action whose previous outcome is unknown."""

        with self._cursor(commit=True) as (_, cursor):
            cursor.execute(
                """
                SELECT remediation_id
                FROM remediation_requests
                WHERE status = 'RUNNING'
                  AND lease_expires_at < CURRENT_TIMESTAMP
                FOR UPDATE
                """
            )
            stale_ids = [row["remediation_id"] for row in cursor.fetchall()]
            for remediation_id in stale_ids:
                cursor.execute(
                    """
                    UPDATE remediation_requests
                    SET status = 'MANUAL_REVIEW',
                        completed_at = CURRENT_TIMESTAMP,
                        error_message = %s
                    WHERE remediation_id = %s
                      AND status = 'RUNNING'
                    """,
                    (
                        "The executor lease expired. The action may have run; "
                        "inspect the target and evidence before creating another request.",
                        remediation_id,
                    ),
                )
                if cursor.rowcount == 1:
                    self._insert_event(
                        cursor,
                        remediation_id,
                        "RUNNING",
                        "MANUAL_REVIEW",
                        self.settings.executor_id,
                        "Executor lease expired; automatic replay was blocked",
                    )
            return len(stale_ids)

    def expire_stale_approvals(self) -> int:
        """Fail approvals that were not claimed within the configured TTL."""

        with self._cursor(commit=True) as (_, cursor):
            cursor.execute(
                """
                SELECT remediation_id
                FROM remediation_requests
                WHERE status = 'APPROVED'
                  AND (
                        approved_at IS NULL
                        OR approved_at < TIMESTAMPADD(
                            SECOND,
                            %s,
                            CURRENT_TIMESTAMP
                        )
                  )
                FOR UPDATE
                """,
                (-self.settings.approval_ttl_seconds,),
            )
            stale_ids = [row["remediation_id"] for row in cursor.fetchall()]
            for remediation_id in stale_ids:
                message = (
                    "Approval expired before the executor claimed the request. "
                    "No command was executed."
                )
                cursor.execute(
                    """
                    UPDATE remediation_requests
                    SET status = 'FAILED',
                        completed_at = CURRENT_TIMESTAMP,
                        error_message = %s
                    WHERE remediation_id = %s
                      AND status = 'APPROVED'
                    """,
                    (message, remediation_id),
                )
                if cursor.rowcount == 1:
                    self._insert_event(
                        cursor,
                        remediation_id,
                        "APPROVED",
                        "FAILED",
                        self.settings.executor_id,
                        message,
                    )
            return len(stale_ids)

    def claim_next_approved(self) -> Optional[dict[str, Any]]:
        execution_token = str(uuid.uuid4())
        with self._cursor(commit=True) as (_, cursor):
            cursor.execute(
                """
                SELECT
                    r.remediation_id,
                    r.incident_id,
                    r.component_id_snapshot,
                    r.action_id,
                    r.target_id,
                    r.implementation_version_snapshot,
                    a.component_id AS catalog_component_id,
                    a.target_id AS catalog_target_id,
                    a.implementation_version AS catalog_implementation_version,
                    a.lifecycle_status,
                    a.executor_type,
                    a.execution_spec
                FROM remediation_requests r
                INNER JOIN remediation_action_catalog a
                    ON a.action_id = r.action_id
                WHERE r.status = 'APPROVED'
                  AND r.approved_at IS NOT NULL
                  AND r.approved_at >= TIMESTAMPADD(
                        SECOND,
                        %s,
                        CURRENT_TIMESTAMP
                  )
                ORDER BY r.approved_at, r.remediation_id
                LIMIT 1
                FOR UPDATE
                """,
                (-self.settings.approval_ttl_seconds,),
            )
            request = cursor.fetchone()
            if request is None:
                return None

            cursor.execute(
                """
                UPDATE remediation_requests
                SET status = 'RUNNING',
                    executor_id = %s,
                    execution_token = %s,
                    started_at = CURRENT_TIMESTAMP,
                    lease_expires_at = DATE_ADD(
                        CURRENT_TIMESTAMP,
                        INTERVAL %s SECOND
                    )
                WHERE remediation_id = %s
                  AND status = 'APPROVED'
                  AND approved_at IS NOT NULL
                  AND approved_at >= TIMESTAMPADD(
                        SECOND,
                        %s,
                        CURRENT_TIMESTAMP
                  )
                """,
                (
                    self.settings.executor_id,
                    execution_token,
                    self.settings.lease_seconds,
                    request["remediation_id"],
                    -self.settings.approval_ttl_seconds,
                ),
            )
            if cursor.rowcount != 1:
                return None

            self._insert_event(
                cursor,
                request["remediation_id"],
                "APPROVED",
                "RUNNING",
                self.settings.executor_id,
                "Executor claimed the approved request",
            )
            request["execution_token"] = execution_token
            return request

    def assert_current_evidence(self, request: dict[str, Any]) -> None:
        """Fail closed when a claimed request has unimported batch details.

        This uses a new database transaction immediately before the SSH
        command, after the executor's live diagnostic prechecks.
        """

        with self._cursor() as (_, cursor):
            cursor.execute(
                """
                SELECT r.status AS request_status,
                       i.pipeline_status, i.site_code, i.err_batch_no,
                       i.error_message
                FROM remediation_requests r
                INNER JOIN live_incidents i ON i.incident_id = r.incident_id
                WHERE r.remediation_id = %s
                  AND r.execution_token = %s
                LIMIT 1
                """,
                (request["remediation_id"], request["execution_token"]),
            )
            incident = cursor.fetchone()
            if incident is None or incident["request_status"] != "RUNNING":
                raise RuntimeError("The executor no longer owns this request")
            if incident["pipeline_status"] != "VERIFIED":
                raise RuntimeError(
                    "The incident is no longer VERIFIED; no command was executed"
                )

            site_code = incident.get("site_code")
            err_batch_no = incident.get("err_batch_no")
            if not site_code or not err_batch_no:
                raise RuntimeError(
                    "The incident has no source batch identity; no command was executed"
                )

            try:
                evidence = incident["error_message"]
                if isinstance(evidence, str):
                    evidence = json.loads(evidence)
                details = evidence["details"]
                if not isinstance(details, list) or not details:
                    raise ValueError("Missing stored detail rows")
                imported_ids = {int(detail["row_id"]) for detail in details}
                if len(imported_ids) != len(details):
                    raise ValueError("Duplicate or invalid stored detail IDs")
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "The incident evidence cannot be verified; "
                    "no command was executed"
                ) from exc

            cursor.execute(
                """
                SELECT row_id FROM t_batch_detail
                WHERE site_code = %s AND err_batch_no = %s
                ORDER BY row_id
                """,
                (site_code, err_batch_no),
            )
            source_ids = {int(row["row_id"]) for row in cursor.fetchall()}
            if imported_ids != source_ids:
                new_ids = sorted(source_ids - imported_ids)
                raise RuntimeError(
                    "Source batch details changed after analysis "
                    f"(new row IDs: {new_ids}); no command was executed. "
                    "Refresh the incident and obtain a new engineer approval."
                )

    def save_result(
        self,
        remediation_id: int,
        execution_token: str,
        result: dict[str, Any],
    ) -> None:
        final_status = final_result_status(result)
        with self._cursor(commit=True) as (_, cursor):
            cursor.execute(
                """
                UPDATE remediation_requests
                SET status = %s,
                    completed_at = CURRENT_TIMESTAMP,
                    lease_expires_at = NULL,
                    exit_code = %s,
                    stdout_text = %s,
                    stderr_text = %s,
                    verification_result = %s,
                    error_message = %s
                WHERE remediation_id = %s
                  AND status = 'RUNNING'
                  AND execution_token = %s
                """,
                (
                    final_status,
                    result.get("exit_code"),
                    result.get("stdout", ""),
                    result.get("stderr", ""),
                    json.dumps(
                        result.get("verification"),
                        ensure_ascii=False,
                    ),
                    result.get("error"),
                    remediation_id,
                    execution_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    "The request is no longer owned by this execution token"
                )
            self._insert_event(
                cursor,
                remediation_id,
                "RUNNING",
                final_status,
                self.settings.executor_id,
                self._result_message(result),
                {"verification": result.get("verification")},
            )

    @staticmethod
    def _result_message(result: dict[str, Any]) -> str:
        verification = result.get("verification") or {}
        outcome = verification.get("outcome")
        if outcome == "ALREADY_HEALTHY":
            return (
                "Live pre-action checks confirmed the target was already "
                "healthy; no command was executed"
            )
        if outcome == "RECOVERED":
            return "Registered action and all post-action checks succeeded"
        return result.get("error") or "Registered action failed"

# RCA_ADMIN_EXECUTION_MODE_V1
