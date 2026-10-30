"""Move imported incidents through Proposer, Verifier and final assessment."""

from __future__ import annotations

import json
import hashlib
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import mysql.connector
from dotenv import load_dotenv

try:
    from .proposer import ProposedRcaDossier, run_proposer_agent
    from .verifier_agent import (
        TransientVerifierLLMError,
        run_verifier_with_findings,
    )
    from .final_assessment import (
        TransientAssessmentLLMError,
        run_final_assessment,
    )
except ImportError:
    from proposer import ProposedRcaDossier, run_proposer_agent
    from verifier_agent import (
        TransientVerifierLLMError,
        run_verifier_with_findings,
    )
    from final_assessment import (
        TransientAssessmentLLMError,
        run_final_assessment,
    )


# Always load agents/.env, regardless of the current working directory.
ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE, override=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("rca.orchestrator")


DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "connection_timeout": 5,
    "charset": "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
    "use_unicode": True,
    "use_pure": True,
}

POLL_SECONDS = int(os.getenv("ORCHESTRATOR_POLL_SECONDS", "10"))
BETWEEN_INCIDENTS_SECONDS = int(
    os.getenv("ORCHESTRATOR_BETWEEN_INCIDENTS_SECONDS", "2")
)
RETRY_LEASE_SECONDS = int(os.getenv("VERIFIER_RETRY_LEASE_SECONDS", "3600"))
MAX_RETRY_FAILURES = int(os.getenv("VERIFIER_RETRY_MAX_FAILURES", "5"))
RETRY_DELAYS_SECONDS = (60, 300, 900, 3600)
MAX_CHECKPOINT_BYTES = 16_000_000


class IncidentStateConflict(RuntimeError):
    """Raised when an incident was changed by another process."""


class IncidentEvidenceChanged(RuntimeError):
    """The imported incident no longer covers its current source batch."""


SOURCE_BATCH_UPDATED_MESSAGE = (
    "## Source Batch Updated\n\n"
    "The source detail row IDs differ from this incident's evidence. "
    "The previous analysis was stopped. The batch importer must "
    "refresh its evidence before the pipeline runs again."
)


def _evidence_hash(value: Any) -> str:
    """Use the same snapshot identity as Verifier and final_assessment."""

    raw = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if isinstance(value, dict)
        else str(value or "")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _assert_snapshot_matches(incident: dict[str, Any], expected_hash: str) -> None:
    if _evidence_hash(incident.get("error_message")) != expected_hash:
        raise IncidentEvidenceChanged(
            "The incident evidence changed during the analysis"
        )


def _assert_source_rows_match(cursor: Any, incident: dict[str, Any]) -> None:
    """Check the imported row IDs against the replicated source batch."""

    site_code = incident.get("site_code")
    err_batch_no = incident.get("err_batch_no")
    if not site_code or not err_batch_no:
        raise IncidentEvidenceChanged("Incident has no source batch identity")

    try:
        payload = incident["error_message"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        details = payload["details"]
        if not isinstance(details, list) or not details:
            raise ValueError("No imported detail rows")
        imported_ids = {int(detail["row_id"]) for detail in details}
        if len(imported_ids) != len(details):
            raise ValueError("Duplicate or invalid detail row IDs")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IncidentEvidenceChanged(
            "The imported detail row IDs cannot be read"
        ) from exc

    cursor.execute(
        """
        SELECT row_id
        FROM t_batch_detail
        WHERE site_code = %s AND err_batch_no = %s
        ORDER BY row_id
        """,
        (site_code, err_batch_no),
    )
    source_ids = {int(row["row_id"]) for row in cursor.fetchall()}
    if source_ids != imported_ids:
        raise IncidentEvidenceChanged(
            "Source detail row IDs differ from the imported evidence "
            f"(new IDs: {sorted(source_ids - imported_ids)})"
        )


def _validate_configuration() -> None:
    missing = [
        name
        for name in ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
        if not os.getenv(name)
    ]
    if missing:
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing)
        )
    if POLL_SECONDS < 1:
        raise RuntimeError("ORCHESTRATOR_POLL_SECONDS must be at least 1")
    if BETWEEN_INCIDENTS_SECONDS < 0:
        raise RuntimeError(
            "ORCHESTRATOR_BETWEEN_INCIDENTS_SECONDS cannot be negative"
        )
    if RETRY_LEASE_SECONDS < 1200:
        raise RuntimeError("VERIFIER_RETRY_LEASE_SECONDS must be at least 1200")
    if MAX_RETRY_FAILURES < 1:
        raise RuntimeError("VERIFIER_RETRY_MAX_FAILURES must be at least 1")


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def _sop_hash(sop: str) -> str:
    return hashlib.sha256(sop.encode("utf-8")).hexdigest()


def _read_sop(cursor: Any, component_id: str) -> str:
    cursor.execute(
        "SELECT investigation_sop FROM t_sops_master "
        "WHERE DAG_id = %s LIMIT 1",
        (component_id,),
    )
    record = cursor.fetchone()
    return str(record.get("investigation_sop") or "").strip() if record else ""


def _claim_next_incident() -> Optional[dict[str, Any]]:
    """Atomically move one NEW incident to ANALYZING and return its data."""

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        cursor.execute(
            """
            SELECT
                incident_id,
                site_code,
                err_batch_no,
                source_system,
                component_id,
                exception_type,
                error_message
            FROM live_incidents
            WHERE pipeline_status = 'NEW'
            ORDER BY incident_id
            LIMIT 1
            FOR UPDATE
            """
        )
        incident = cursor.fetchone()
        if incident is None:
            connection.rollback()
            return None

        try:
            _assert_source_rows_match(cursor, incident)
        except IncidentEvidenceChanged as exc:
            LOGGER.warning(
                "Deferring incident %s until its batch is refreshed: %s",
                incident["incident_id"],
                exc,
            )
            cursor.execute(
                """
                UPDATE live_incidents
                SET pipeline_status = 'ERROR', ai_verifier_result = %s,
                    ai_verifier_findings = NULL,
                    ai_final_assessment = NULL
                WHERE incident_id = %s AND pipeline_status = 'NEW'
                """,
                (SOURCE_BATCH_UPDATED_MESSAGE, incident["incident_id"]),
            )
            if cursor.rowcount != 1:
                raise IncidentStateConflict("Incident changed during its claim")
            connection.commit()
            return None

        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'ANALYZING'
            WHERE incident_id = %s
              AND pipeline_status = 'NEW'
            """,
            (incident["incident_id"],),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return None

        connection.commit()
        return incident
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _claim_due_verification() -> Optional[dict[str, Any]]:
    """Claim one scheduled retry or an expired in-flight verification lease."""

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        cursor.execute(
            """
            SELECT r.incident_id
            FROM incident_verification_retries r
            JOIN live_incidents i ON i.incident_id = r.incident_id
            WHERE i.pipeline_status = 'AWAITING_VERIFICATION'
              AND (
                  (r.lease_expires_at IS NULL
                   AND r.next_attempt_at <= CURRENT_TIMESTAMP)
                  OR r.lease_expires_at <= CURRENT_TIMESTAMP
              )
            ORDER BY COALESCE(r.next_attempt_at, r.lease_expires_at), r.incident_id
            LIMIT 1
            """
        )
        candidate = cursor.fetchone()
        if candidate is None:
            connection.rollback()
            return None

        incident_id = candidate["incident_id"]
        cursor.execute(
            """
            SELECT incident_id, site_code, err_batch_no, source_system,
                   component_id, exception_type, error_message,
                   ai_proposed_root_cause, pipeline_status
            FROM live_incidents WHERE incident_id = %s FOR UPDATE
            """,
            (incident_id,),
        )
        incident = cursor.fetchone()
        cursor.execute(
            """
            SELECT incident_evidence_sha256, sop_sha256, failure_count,
                   next_attempt_at, lease_expires_at, tool_history,
                   verifier_result
            FROM incident_verification_retries
            WHERE incident_id = %s FOR UPDATE
            """,
            (incident_id,),
        )
        retry = cursor.fetchone()
        if incident is None or retry is None or incident["pipeline_status"] != "AWAITING_VERIFICATION":
            connection.rollback()
            return None
        cursor.execute(
            """
            SELECT 1 AS due
            FROM incident_verification_retries
            WHERE incident_id = %s AND (
                (lease_expires_at IS NULL AND next_attempt_at <= CURRENT_TIMESTAMP)
                OR lease_expires_at <= CURRENT_TIMESTAMP
            )
            """,
            (incident_id,),
        )
        if cursor.fetchone() is None:
            connection.rollback()
            return None

        try:
            _assert_source_rows_match(cursor, incident)
            _assert_snapshot_matches(incident, retry["incident_evidence_sha256"])
        except IncidentEvidenceChanged:
            cursor.execute(
                """
                UPDATE live_incidents
                SET pipeline_status = 'ERROR', ai_verifier_result = %s,
                    ai_verifier_findings = NULL, ai_final_assessment = NULL
                WHERE incident_id = %s AND pipeline_status = 'AWAITING_VERIFICATION'
                """,
                (SOURCE_BATCH_UPDATED_MESSAGE, incident_id),
            )
            cursor.execute(
                "DELETE FROM incident_verification_retries WHERE incident_id = %s",
                (incident_id,),
            )
            connection.commit()
            return None

        token = str(uuid.uuid4())
        cursor.execute(
            """
            UPDATE incident_verification_retries
            SET lease_token = %s,
                lease_expires_at = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL %s SECOND),
                next_attempt_at = NULL
            WHERE incident_id = %s
            """,
            (token, RETRY_LEASE_SECONDS, incident_id),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict("Verification retry was claimed elsewhere")
        connection.commit()
        incident.update(retry)
        incident["lease_token"] = token
        incident["is_verification_retry"] = True
        return incident
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _parse_proposer_output(proposer_output: str) -> ProposedRcaDossier:
    """Validate the Proposer's strict JSON contract before saving it."""

    return ProposedRcaDossier.model_validate_json(proposer_output)


def _save_proposal_and_get_sop(
    incident_id: int,
    component_id: str,
    dossier: ProposedRcaDossier,
    expected_evidence_hash: str,
) -> tuple[str, str]:
    """Save the complete proposal, advance state, and load the SOP.

    The API normalizer expects ``ai_proposed_root_cause`` to contain the
    complete strict Proposer JSON. Keeping the dossier intact preserves the
    confidence score and historical-match flag for the dashboard while
    ``ai_proposed_fix`` remains populated for backwards compatibility.
    """

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    serialized_dossier = dossier.model_dump_json()
    try:
        cursor.execute(
            """
            SELECT site_code, err_batch_no, error_message, pipeline_status
            FROM live_incidents
            WHERE incident_id = %s
            FOR UPDATE
            """,
            (incident_id,),
        )
        incident = cursor.fetchone()
        if incident is None or incident["pipeline_status"] != "ANALYZING":
            raise IncidentStateConflict("Incident is no longer in ANALYZING state")
        _assert_source_rows_match(cursor, incident)
        _assert_snapshot_matches(incident, expected_evidence_hash)

        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'AWAITING_VERIFICATION',
                ai_proposed_root_cause = %s,
                ai_proposed_fix = %s,
                ai_verifier_result = NULL,
                ai_verifier_findings = NULL,
                ai_final_assessment = NULL
            WHERE incident_id = %s
              AND pipeline_status = 'ANALYZING'
            """,
            (
                serialized_dossier,
                dossier.proposed_actionable_fix,
                incident_id,
            ),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict(
                "Incident is no longer in ANALYZING state"
            )

        sop = _read_sop(cursor, component_id)
        token = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO incident_verification_retries (
                incident_id, incident_evidence_sha256, sop_sha256,
                failure_count, next_attempt_at, lease_expires_at,
                lease_token, tool_history, verifier_result, last_error
            ) VALUES (
                %s, %s, %s, 0, NULL,
                DATE_ADD(CURRENT_TIMESTAMP, INTERVAL %s SECOND),
                %s, NULL, NULL, NULL
            ) ON DUPLICATE KEY UPDATE
                incident_evidence_sha256 = VALUES(incident_evidence_sha256),
                sop_sha256 = VALUES(sop_sha256),
                failure_count = 0,
                next_attempt_at = NULL,
                lease_expires_at = VALUES(lease_expires_at),
                lease_token = VALUES(lease_token),
                tool_history = NULL,
                verifier_result = NULL,
                last_error = NULL
            """,
            (incident_id, expected_evidence_hash, _sop_hash(sop),
             RETRY_LEASE_SECONDS, token),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()

    return sop, token


def _retry_sop_and_checkpoints(
    incident: dict[str, Any], expected_hash: str, token: str,
) -> tuple[str, Optional[list[dict[str, Any]]], Optional[dict[str, Any]]]:
    """Resume only checkpoints for the current evidence and current SOP."""

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT site_code, err_batch_no, error_message, pipeline_status
            FROM live_incidents WHERE incident_id = %s FOR UPDATE
            """,
            (incident["incident_id"],),
        )
        current = cursor.fetchone()
        if current is None or current["pipeline_status"] != "AWAITING_VERIFICATION":
            raise IncidentStateConflict("Incident is no longer awaiting verification")
        _assert_source_rows_match(cursor, current)
        _assert_snapshot_matches(current, expected_hash)
        cursor.execute(
            """
            SELECT lease_token, incident_evidence_sha256, sop_sha256,
                   tool_history, verifier_result
            FROM incident_verification_retries
            WHERE incident_id = %s FOR UPDATE
            """,
            (incident["incident_id"],),
        )
        retry = cursor.fetchone()
        if retry is None or retry["lease_token"] != token:
            raise IncidentStateConflict("Verification lease was replaced")
        if retry["incident_evidence_sha256"] != expected_hash:
            raise IncidentEvidenceChanged("Retry checkpoint belongs to different evidence")

        sop = _read_sop(cursor, str(incident["component_id"]))
        if retry["sop_sha256"] != _sop_hash(sop):
            cursor.execute(
                """
                UPDATE incident_verification_retries
                SET sop_sha256 = %s, tool_history = NULL, verifier_result = NULL
                WHERE incident_id = %s AND lease_token = %s
                """,
                (_sop_hash(sop), incident["incident_id"], token),
            )
            cursor.execute(
                """
                UPDATE live_incidents
                SET ai_verifier_result = NULL, ai_verifier_findings = NULL,
                    ai_final_assessment = NULL
                WHERE incident_id = %s AND pipeline_status = 'AWAITING_VERIFICATION'
                """,
                (incident["incident_id"],),
            )
            connection.commit()
            return sop, None, None

        history = json.loads(retry["tool_history"]) if retry["tool_history"] else None
        verifier = json.loads(retry["verifier_result"]) if retry["verifier_result"] else None
        if history is not None and not isinstance(history, list):
            raise RuntimeError("Stored Verifier history is invalid")
        if verifier is not None and (
            not isinstance(verifier, dict)
            or verifier.get("schema_version") != 1
            or verifier.get("incident_evidence_sha256") != expected_hash
        ):
            raise RuntimeError("Stored Verifier checkpoint is invalid")
        connection.commit()
        return sop, history, verifier
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _save_verifier_checkpoint(
    incident_id: int, verifier: dict[str, Any], expected_hash: str, token: str,
) -> None:
    """Retain diagnostics if final assessment needs a later retry."""

    if verifier.get("schema_version") != 1 or verifier.get("incident_evidence_sha256") != expected_hash:
        raise IncidentEvidenceChanged("Verifier result belongs to different evidence")
    report = verifier.get("report_markdown")
    if not isinstance(report, str) or not report.strip():
        raise ValueError("Verifier did not produce a readable report")
    serialized = json.dumps(verifier, ensure_ascii=False, default=str)
    history = json.dumps(verifier.get("tool_history"), ensure_ascii=False, default=str)
    if len(serialized.encode("utf-8")) > MAX_CHECKPOINT_BYTES:
        raise ValueError("Verifier result exceeds a MEDIUMTEXT limit")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT site_code, err_batch_no, error_message, pipeline_status
            FROM live_incidents WHERE incident_id = %s FOR UPDATE
            """,
            (incident_id,),
        )
        current = cursor.fetchone()
        if current is None or current["pipeline_status"] != "AWAITING_VERIFICATION":
            raise IncidentStateConflict("Incident is no longer awaiting verification")
        _assert_source_rows_match(cursor, current)
        _assert_snapshot_matches(current, expected_hash)
        cursor.execute(
            """
            UPDATE incident_verification_retries
            SET tool_history = %s, verifier_result = %s
            WHERE incident_id = %s AND lease_token = %s
            """,
            (history, serialized, incident_id, token),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict("Verification lease was replaced")
        cursor.execute(
            """
            UPDATE live_incidents
            SET ai_verifier_result = %s, ai_verifier_findings = %s
            WHERE incident_id = %s AND pipeline_status = 'AWAITING_VERIFICATION'
            """,
            (report, serialized, incident_id),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _save_verifier_and_assessment(
    incident_id: int,
    verifier_result: dict[str, Any],
    assessment: dict[str, Any],
    expected_evidence_hash: str,
    token: str,
) -> None:
    """Atomically save both answers for the same current source batch."""

    if verifier_result.get("schema_version") != 1:
        raise ValueError("Unsupported structured Verifier result")
    if assessment.get("schema_version") != 1:
        raise ValueError("Unsupported final assessment result")
    if (
        verifier_result.get("incident_evidence_sha256") != expected_evidence_hash
        or assessment.get("incident_evidence_sha256") != expected_evidence_hash
    ):
        raise IncidentEvidenceChanged(
            "The Verifier and final assessment refer to different evidence"
        )
    report = verifier_result.get("report_markdown")
    if not isinstance(report, str) or not report.strip():
        raise ValueError("The Verifier did not produce a readable report")
    serialized_verifier = json.dumps(
        verifier_result, ensure_ascii=False, default=str
    )
    serialized_assessment = json.dumps(
        assessment, ensure_ascii=False, default=str
    )
    if (
        len(serialized_verifier.encode("utf-8")) > 16_000_000
        or len(serialized_assessment.encode("utf-8")) > 16_000_000
    ):
        raise ValueError("The structured analysis exceeds a MEDIUMTEXT limit")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT site_code, err_batch_no, error_message, pipeline_status
            FROM live_incidents
            WHERE incident_id = %s
            FOR UPDATE
            """,
            (incident_id,),
        )
        incident = cursor.fetchone()
        if incident is None or incident["pipeline_status"] != "AWAITING_VERIFICATION":
            raise IncidentStateConflict(
                "Incident is no longer awaiting verification"
            )
        _assert_source_rows_match(cursor, incident)
        _assert_snapshot_matches(incident, expected_evidence_hash)

        cursor.execute(
            "SELECT lease_token FROM incident_verification_retries "
            "WHERE incident_id = %s FOR UPDATE",
            (incident_id,),
        )
        retry = cursor.fetchone()
        if retry is None or retry["lease_token"] != token:
            raise IncidentStateConflict("Verification lease was replaced")

        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'VERIFIED',
                ai_verifier_result = %s,
                ai_verifier_findings = %s,
                ai_final_assessment = %s
            WHERE incident_id = %s
              AND pipeline_status = 'AWAITING_VERIFICATION'
            """,
            (report, serialized_verifier, serialized_assessment, incident_id),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict(
                "Incident is no longer awaiting verification"
            )
        cursor.execute(
            "DELETE FROM incident_verification_retries "
            "WHERE incident_id = %s AND lease_token = %s",
            (incident_id, token),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict("Verification lease was replaced")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _mark_incident_error(
    incident_id: int,
    *,
    source_batch_changed: bool = False,
    expected_token: Optional[str] = None,
) -> None:
    """Move an owned in-flight incident to ERROR without exposing secrets."""

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # Every other retry transaction locks the incident before the retry
        # record. Use the same order to avoid a lock inversion here.
        cursor.execute(
            "SELECT incident_id FROM live_incidents "
            "WHERE incident_id = %s FOR UPDATE",
            (incident_id,),
        )
        if cursor.fetchone() is None:
            connection.rollback()
            return
        if expected_token is not None:
            cursor.execute(
                "SELECT lease_token FROM incident_verification_retries "
                "WHERE incident_id = %s FOR UPDATE",
                (incident_id,),
            )
            retry = cursor.fetchone()
            if retry is None or retry[0] != expected_token:
                connection.rollback()
                LOGGER.warning("Skipping error update for superseded lease on %s", incident_id)
                return
        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'ERROR',
                ai_verifier_result = %s,
                ai_verifier_findings = NULL,
                ai_final_assessment = NULL
            WHERE incident_id = %s
              AND pipeline_status IN ('ANALYZING', 'AWAITING_VERIFICATION')
            """,
            (
                SOURCE_BATCH_UPDATED_MESSAGE
                if source_batch_changed
                else (
                    "## Pipeline Error\n\n"
                    "The orchestrator stopped safely. Inspect the orchestrator "
                    "logs before retrying this incident."
                ),
                incident_id,
            ),
        )
        if expected_token is not None and cursor.rowcount == 1:
            cursor.execute(
                "DELETE FROM incident_verification_retries "
                "WHERE incident_id = %s AND lease_token = %s",
                (incident_id, expected_token),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        LOGGER.exception(
            "Could not move incident %s to ERROR",
            incident_id,
        )
    finally:
        cursor.close()
        connection.close()


def _schedule_verification_retry(
    incident_id: int,
    expected_hash: str,
    token: str,
    error: Exception,
) -> None:
    """Persist bounded backoff without treating a model outage as a diagnosis."""

    history = getattr(error, "tool_history", None)
    error_hash = getattr(error, "incident_evidence_sha256", None)
    if error_hash is not None and error_hash != expected_hash:
        raise IncidentEvidenceChanged("Verifier retry belongs to different evidence")
    serialized_history = (
        json.dumps(history, ensure_ascii=False, default=str)
        if history is not None else None
    )
    if serialized_history is not None and len(serialized_history.encode("utf-8")) > MAX_CHECKPOINT_BYTES:
        raise ValueError("Verifier retry history exceeds a MEDIUMTEXT limit")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT site_code, err_batch_no, error_message, pipeline_status
            FROM live_incidents WHERE incident_id = %s FOR UPDATE
            """,
            (incident_id,),
        )
        incident = cursor.fetchone()
        if incident is None or incident["pipeline_status"] != "AWAITING_VERIFICATION":
            raise IncidentStateConflict("Incident is no longer awaiting verification")
        _assert_source_rows_match(cursor, incident)
        _assert_snapshot_matches(incident, expected_hash)
        cursor.execute(
            """
            SELECT failure_count, lease_token, incident_evidence_sha256
            FROM incident_verification_retries
            WHERE incident_id = %s FOR UPDATE
            """,
            (incident_id,),
        )
        retry = cursor.fetchone()
        if retry is None or retry["lease_token"] != token:
            raise IncidentStateConflict("Verification lease was replaced")
        if retry["incident_evidence_sha256"] != expected_hash:
            raise IncidentEvidenceChanged("Retry checkpoint belongs to different evidence")

        failures = int(retry["failure_count"]) + 1
        if failures >= MAX_RETRY_FAILURES:
            cursor.execute(
                """
                UPDATE live_incidents
                SET pipeline_status = 'ERROR',
                    ai_verifier_result = CASE
                        WHEN ai_verifier_findings IS NULL THEN %s
                        ELSE ai_verifier_result
                    END,
                    ai_final_assessment = NULL
                WHERE incident_id = %s AND pipeline_status = 'AWAITING_VERIFICATION'
                """,
                (
                    "## Verification unavailable\n\n"
                    "The model service failed repeatedly. An operator must "
                    "review the pipeline log and retry this incident.",
                    incident_id,
                ),
            )
            if cursor.rowcount != 1:
                raise IncidentStateConflict("Incident changed before retry exhaustion")
            cursor.execute(
                "DELETE FROM incident_verification_retries "
                "WHERE incident_id = %s AND lease_token = %s",
                (incident_id, token),
            )
            LOGGER.error("Verification exhausted retries for incident %s: %s", incident_id, error)
        else:
            delay = RETRY_DELAYS_SECONDS[min(failures - 1, len(RETRY_DELAYS_SECONDS) - 1)]
            cursor.execute(
                """
                UPDATE incident_verification_retries
                SET failure_count = %s,
                    next_attempt_at = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL %s SECOND),
                    lease_expires_at = NULL,
                    lease_token = NULL,
                    tool_history = COALESCE(%s, tool_history),
                    last_error = %s
                WHERE incident_id = %s AND lease_token = %s
                """,
                (failures, delay, serialized_history, str(error)[:500], incident_id, token),
            )
            if cursor.rowcount != 1:
                raise IncidentStateConflict("Verification lease was replaced")
            LOGGER.warning(
                "Verification for incident %s deferred %d seconds after failure %d: %s",
                incident_id, delay, failures, error,
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def process_incident() -> bool:
    """Process one due verification or NEW incident per runner cycle."""

    incident = _claim_due_verification() or _claim_next_incident()
    if incident is None:
        return False

    incident_id = int(incident["incident_id"])
    component_id = str(incident["component_id"])
    original_error_message = incident.get("error_message") or ""
    evidence_hash = _evidence_hash(original_error_message)
    token: Optional[str] = incident.get("lease_token")
    LOGGER.info(
        "Claimed incident %s for site=%s batch=%s component=%s retry=%s",
        incident_id,
        incident.get("site_code"),
        incident.get("err_batch_no"),
        component_id,
        bool(incident.get("is_verification_retry")),
    )

    try:
        if incident.get("is_verification_retry"):
            dossier = _parse_proposer_output(incident["ai_proposed_root_cause"])
            raw_sop_text, history, verifier_result = _retry_sop_and_checkpoints(
                incident, evidence_hash, token,
            )
        else:
            proposer_output = run_proposer_agent(
                source_system=str(incident["source_system"]),
                component_id=component_id,
                exception_type=str(incident.get("exception_type") or ""),
                error_message=original_error_message,
            )
            dossier = _parse_proposer_output(proposer_output)
            raw_sop_text, token = _save_proposal_and_get_sop(
                incident_id, component_id, dossier, evidence_hash,
            )
            history = None
            verifier_result = None
            LOGGER.info("Incident %s moved to AWAITING_VERIFICATION", incident_id)

        if not raw_sop_text:
            LOGGER.warning(
                "No strict SOP exists in t_sops_master for component %s; "
                "the Verifier will return an inconclusive report",
                component_id,
            )

        if verifier_result is None:
            verifier_result = run_verifier_with_findings(
                incident_error_message=original_error_message,
                proposed_rca=dossier.proposed_root_cause,
                proposed_fix=dossier.proposed_actionable_fix,
                raw_db_sop=raw_sop_text,
                initial_tool_history=history,
            )
            _save_verifier_checkpoint(incident_id, verifier_result, evidence_hash, token)

        assessment = run_final_assessment(
            proposer_dossier=dossier,
            verifier_result=verifier_result,
            incident_error_message=original_error_message,
        )
        _save_verifier_and_assessment(
            incident_id,
            verifier_result,
            assessment,
            evidence_hash,
            token,
        )
        LOGGER.info(
            "Incident %s moved to VERIFIED",
            incident_id,
        )
        return True
    except (TransientVerifierLLMError, TransientAssessmentLLMError) as exc:
        try:
            _schedule_verification_retry(incident_id, evidence_hash, token, exc)
        except IncidentEvidenceChanged:
            LOGGER.warning("Source evidence changed during retry for incident %s", incident_id)
            _mark_incident_error(incident_id, source_batch_changed=True, expected_token=token)
        except IncidentStateConflict:
            LOGGER.warning("Retry lease or state changed for incident %s", incident_id)
        except Exception:
            LOGGER.exception("Could not schedule retry for incident %s", incident_id)
            _mark_incident_error(incident_id, expected_token=token)
        return True
    except IncidentEvidenceChanged:
        LOGGER.warning(
            "Source batch changed while analyzing incident %s; "
            "waiting for the importer to refresh it",
            incident_id,
        )
        _mark_incident_error(incident_id, source_batch_changed=True, expected_token=token)
        return True
    except IncidentStateConflict:
        LOGGER.warning("Incident %s changed during processing", incident_id)
        return True
    except Exception:
        LOGGER.exception("Pipeline failed for incident %s", incident_id)
        _mark_incident_error(incident_id, expected_token=token)
        return True


def run_forever() -> None:
    """Continuously process imported incidents until interrupted."""

    _validate_configuration()
    LOGGER.info("RCA Pipeline Orchestrator started")
    LOGGER.info("Listening for NEW incidents and due verification retries")

    while True:
        try:
            processed = process_incident()
        except Exception:
            LOGGER.exception(
                "Orchestrator polling failed; retrying after %s seconds",
                POLL_SECONDS,
            )
            processed = False
        time.sleep(
            BETWEEN_INCIDENTS_SECONDS if processed else POLL_SECONDS
        )


if __name__ == "__main__":
    try:
        run_forever()
    except KeyboardInterrupt:
        LOGGER.info("Orchestrator shut down manually")
