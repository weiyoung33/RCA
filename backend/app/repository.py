from __future__ import annotations

import json
import hashlib
import uuid
from datetime import date, datetime, timedelta
from typing import Any, Optional

from .db import database_cursor
from .normalizers import normalize_incident, sha256_text
from .test_cases import get_test_case


INCIDENT_COLUMNS = """
    incident_id, site_code, err_batch_no, source_system, component_id,
    incident_time, exception_type, error_message, severity, pipeline_status,
    ai_proposed_root_cause, ai_proposed_fix, ai_verifier_result,
    actual_root_cause, actual_action_taken, resolved_by, resolved_time
"""

# The incident list uses the compact column set above. Detail requests load
# the full diagnostic record only for the selected incident.
INCIDENT_DETAIL_COLUMNS = (
    INCIDENT_COLUMNS + ", ai_verifier_findings, ai_final_assessment"
)

QUEUE_ACTION_RESOLVED = "RESOLVED"
QUEUE_STATUS_PENDING = "PENDING"


def normalize_review(review: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(review)
    actions = normalized.get("selected_actions")
    if isinstance(actions, str):
        try:
            actions = json.loads(actions)
        except json.JSONDecodeError:
            actions = []
    normalized["selected_actions"] = actions if isinstance(actions, list) else []
    normalized["promoted_to_knowledge_base"] = bool(
        normalized.get("promoted_to_knowledge_base")
    )
    return normalized


def _normalize_incident_record(row: dict[str, Any]) -> dict[str, Any]:
    """Keep the existing API shape and expose the production batch identity."""

    normalized = normalize_incident(row)
    normalized.pop("ai_verifier_findings", None)
    normalized.pop("ai_final_assessment", None)
    normalized.update(
        {
            "site_code": row.get("site_code"),
            "err_batch_no": row.get("err_batch_no"),
            "incident_time": row.get("incident_time"),
            "severity": row.get("severity"),
            "actual_root_cause": row.get("actual_root_cause"),
            "actual_action_taken": row.get("actual_action_taken"),
            "resolved_by": row.get("resolved_by"),
            "resolved_time": row.get("resolved_time"),
        }
    )
    if "ai_verifier_findings" in row:
        findings = _normalize_json(row.get("ai_verifier_findings"), fallback=None)
        normalized["verifier_findings"] = (
            findings if isinstance(findings, dict) else None
        )
    if "ai_final_assessment" in row:
        assessment = _normalize_json(row.get("ai_final_assessment"), fallback=None)
        normalized["final_assessment"] = (
            assessment if isinstance(assessment, dict) else None
        )
    return normalized


def _normalized_actions(selected_actions: list[str]) -> list[str]:
    return [
        action.strip()
        for action in selected_actions
        if isinstance(action, str) and action.strip()
    ]


def _validate_promotion(
    decision: str,
    actions: list[str],
    promote_to_knowledge_base: bool,
) -> None:
    if promote_to_knowledge_base and decision == "rejected":
        raise ValueError(
            "A rejected resolution cannot be promoted to the knowledge base"
        )
    if promote_to_knowledge_base and not actions:
        raise ValueError(
            "Add at least one confirmed action before promoting the resolution"
        )


def _incident_evidence(value: Any) -> dict[str, Any]:
    parsed = _normalize_json(value, fallback={})
    return parsed if isinstance(parsed, dict) else {}


def _evidence_hash(value: Any) -> str:
    """Match the snapshot hash used by the Verifier and orchestrator."""

    raw = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if isinstance(value, dict)
        else str(value or "")
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _analysis_snapshot_current(
    incident: dict[str, Any], evidence_state: dict[str, Any]
) -> bool:
    """Confirm both saved analyses belong to the imported current batch."""

    if evidence_state.get("evidence_stale") is not False:
        return False
    verifier = _normalize_json(incident.get("ai_verifier_findings"), fallback={})
    assessment = _normalize_json(incident.get("ai_final_assessment"), fallback={})
    if not isinstance(verifier, dict) or not isinstance(assessment, dict):
        return False
    digest = _evidence_hash(incident.get("error_message"))
    return (
        verifier.get("schema_version") == 1
        and assessment.get("schema_version") == 1
        and verifier.get("incident_evidence_sha256") == digest
        and assessment.get("incident_evidence_sha256") == digest
        and incident.get("pipeline_status") in {"VERIFIED", "CLOSED"}
    )


def _source_evidence_state(cursor: Any, incident: dict[str, Any]) -> dict[str, Any]:
    """Compare imported evidence with all detail IDs currently in the source.

    Compare IDs, rather than only the count: a changed or missing source row
    must not appear current merely because another row took its place.
    """

    site_code = incident.get("site_code")
    err_batch_no = incident.get("err_batch_no")
    if not site_code or not err_batch_no:
        return {
            "evidence_stale": None,
            "source_detail_count": None,
            "new_source_row_ids": [],
        }

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
    stored_details = _incident_evidence(incident.get("error_message")).get(
        "details"
    )
    stored_ids: set[int] = set()
    valid_snapshot = isinstance(stored_details, list) and bool(stored_details)
    if valid_snapshot:
        try:
            stored_ids = {
                int(detail["row_id"])
                for detail in stored_details
                if isinstance(detail, dict) and detail.get("row_id") is not None
            }
            valid_snapshot = len(stored_ids) == len(stored_details)
        except (KeyError, TypeError, ValueError):
            valid_snapshot = False

    return {
        "evidence_stale": not (valid_snapshot and source_ids == stored_ids),
        "source_detail_count": len(source_ids),
        "new_source_row_ids": sorted(source_ids - stored_ids),
    }


def _require_current_evidence(cursor: Any, incident: dict[str, Any]) -> None:
    state = _source_evidence_state(cursor, incident)
    if state["evidence_stale"] is not False:
        raise ValueError(
            "Source batch details changed or cannot be verified. "
            "Wait for the importer to refresh and the agents to reanalyze "
            "the incident before approving an action or closing it."
        )


def _limited(value: Any, limit: int) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    return text if len(text) <= limit else text[:limit]


def _knowledge_metadata(
    incident: dict[str, Any],
    decision: str,
) -> dict[str, Any]:
    evidence = _incident_evidence(incident.get("error_message"))
    groups = evidence.get("distinct_error_groups")
    categories: list[str] = []
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            category = str(group.get("category") or "").strip()
            if category and category not in categories:
                categories.append(category)

    component_id = str(incident.get("component_id") or "").strip()
    exception_type = str(incident.get("exception_type") or "").strip()
    title = f"{component_id}: {exception_type or 'Root cause analysis'}"

    confidence_score = None
    if decision == "accepted":
        proposer = _normalize_json(
            incident.get("ai_proposed_root_cause"),
            fallback={},
        )
        if isinstance(proposer, dict):
            candidate = proposer.get("historical_confidence_score")
            try:
                numeric = float(candidate)
            except (TypeError, ValueError):
                numeric = None
            if numeric is not None and 1 <= numeric <= 100:
                confidence_score = numeric

    return {
        "rca_title": _limited(title, 500),
        "category": _limited(", ".join(categories), 150),
        "dag_id": _limited(component_id, 150),
        "exception_type": _limited(exception_type, 100),
        "confidence_score": confidence_score,
        "created_site": _limited(
            incident.get("site_code") or incident.get("source_system"),
            20,
        ),
    }


def _insert_rca_master(
    cursor: Any,
    incident: dict[str, Any],
    decision: str,
    final_root_cause: str,
    actions: list[str],
    actor: str,
) -> int:
    metadata = _knowledge_metadata(incident, decision)
    cursor.execute(
        """
        INSERT INTO t_rca_master (
            rca_title,
            category,
            dag_id,
            exception_type,
            root_cause,
            action_taken,
            preventive_action,
            confidence_score,
            created_by,
            created_date,
            updated_date,
            created_site
        ) VALUES (
            %s, %s, %s, %s, %s, %s, NULL, %s, %s,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s
        )
        """,
        (
            metadata["rca_title"],
            metadata["category"],
            metadata["dag_id"],
            metadata["exception_type"],
            final_root_cause,
            "\n".join(actions),
            metadata["confidence_score"],
            _limited(actor, 100),
            metadata["created_site"],
        ),
    )
    return int(cursor.lastrowid)


def _update_rca_master(
    cursor: Any,
    rca_id: int,
    incident: dict[str, Any],
    decision: str,
    final_root_cause: str,
    actions: list[str],
) -> None:
    metadata = _knowledge_metadata(incident, decision)
    cursor.execute(
        """
        UPDATE t_rca_master
        SET rca_title = %s,
            category = %s,
            dag_id = %s,
            exception_type = %s,
            root_cause = %s,
            action_taken = %s,
            confidence_score = %s,
            updated_date = CURRENT_TIMESTAMP
        WHERE rca_id = %s
        """,
        (
            metadata["rca_title"],
            metadata["category"],
            metadata["dag_id"],
            metadata["exception_type"],
            final_root_cause,
            "\n".join(actions),
            metadata["confidence_score"],
            rca_id,
        ),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("The linked RCA knowledge entry could not be updated")


def _ensure_rca_mapping(
    cursor: Any,
    incident: dict[str, Any],
    rca_id: int,
    actor: str,
) -> None:
    site_code = incident.get("site_code")
    err_batch_no = incident.get("err_batch_no")
    if not site_code or not err_batch_no:
        return

    cursor.execute(
        """
        INSERT INTO t_rca_mapping (
            site_code, err_batch_no, rca_id, mapped_by, mapped_date
        )
        SELECT %s, %s, %s, %s, CURRENT_TIMESTAMP
        WHERE NOT EXISTS (
            SELECT 1
            FROM t_rca_mapping
            WHERE site_code = %s
              AND err_batch_no = %s
              AND rca_id = %s
        )
        """,
        (
            site_code,
            err_batch_no,
            rca_id,
            _limited(actor, 100),
            site_code,
            err_batch_no,
            rca_id,
        ),
    )


def _sync_operational_resolution(
    cursor: Any,
    incident: dict[str, Any],
    final_root_cause: str,
    actions: list[str],
    actor: str,
) -> None:
    """Update internal state and enqueue the requested production change."""

    action_text = "\n".join(actions)
    cursor.execute(
        """
        UPDATE live_incidents
        SET pipeline_status = 'CLOSED',
            actual_root_cause = %s,
            actual_action_taken = %s,
            resolved_by = %s,
            resolved_time = CURRENT_TIMESTAMP
        WHERE incident_id = %s
        """,
        (
            final_root_cause,
            action_text,
            _limited(actor, 100),
            incident["incident_id"],
        ),
    )

    site_code = incident.get("site_code")
    err_batch_no = incident.get("err_batch_no")
    if not site_code or not err_batch_no:
        return

    cursor.execute(
        """
        INSERT INTO t_alert_action_queue (
            site_code,
            err_batch_no,
            action_type,
            root_cause,
            action_taken,
            requested_by,
            request_date,
            queue_status
        ) VALUES (
            %s, %s, %s, %s, %s, %s,
            CURRENT_TIMESTAMP, %s
        )
        """,
        (
            site_code,
            err_batch_no,
            QUEUE_ACTION_RESOLVED,
            final_root_cause,
            action_text,
            _limited(actor, 100),
            QUEUE_STATUS_PENDING,
        ),
    )


def _normalize_json(value: Any, fallback: Any = None) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list, bool, int, float)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return fallback


def normalize_remediation(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["verification_result"] = _normalize_json(
        normalized.get("verification_result")
    )
    normalized["requires_approval"] = bool(
        normalized.get("requires_approval", True)
    )
    return normalized


def _insert_remediation_event(
    cursor: Any,
    remediation_id: int,
    from_status: Optional[str],
    to_status: str,
    actor_type: str,
    actor_name: str,
    message: str,
) -> None:
    cursor.execute(
        """
        INSERT INTO remediation_events (
            remediation_id, from_status, to_status,
            actor_type, actor_name, message
        ) VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            remediation_id,
            from_status,
            to_status,
            actor_type,
            actor_name,
            message,
        ),
    )


def list_remediation_actions(
    component_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    where = "WHERE component_id = %s" if component_id else ""
    parameters = (component_id,) if component_id else ()
    with database_cursor() as (_, cursor):
        cursor.execute(
            f"""
            SELECT
                action_id,
                component_id,
                target_id,
                display_name,
                description,
                risk_level,
                lifecycle_status,
                implementation_version,
                verification_summary,
                rollback_summary,
                requires_approval,
                updated_by,
                updated_at
            FROM remediation_action_catalog
            {where}
            ORDER BY
                CASE lifecycle_status
                    WHEN 'ACTIVE' THEN 0
                    WHEN 'DRAFT' THEN 1
                    ELSE 2
                END,
                display_name
            """,
            parameters,
        )
        return [normalize_remediation(row) for row in cursor.fetchall()]


def list_remediation_requests(
    incident_id: Optional[int] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    where = "WHERE incident_id = %s" if incident_id is not None else ""
    parameters: list[Any] = [incident_id] if incident_id is not None else []
    parameters.append(limit)
    with database_cursor() as (_, cursor):
        cursor.execute(
            f"""
            SELECT
                remediation_id,
                incident_id,
                component_id_snapshot,
                action_id,
                target_id,
                action_name_snapshot,
                risk_level_snapshot,
                implementation_version_snapshot,
                status,
                request_reason,
                idempotency_key,
                requested_by,
                requested_at,
                approved_by,
                approved_at,
                approval_comment,
                rejected_by,
                rejected_at,
                rejection_comment,
                manual_resolution_by,
                manual_resolution_at,
                manual_resolution_comment,
                executor_id,
                execution_token,
                lease_expires_at,
                started_at,
                completed_at,
                exit_code,
                stdout_text,
                stderr_text,
                verification_result,
                error_message
            FROM remediation_requests
            {where}
            ORDER BY remediation_id DESC
            LIMIT %s
            """,
            tuple(parameters),
        )
        return [normalize_remediation(row) for row in cursor.fetchall()]


def create_remediation_request(
    incident_id: int,
    action_id: str,
    request_reason: str,
    requested_by: str,
    idempotency_key: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    request_key = idempotency_key or str(uuid.uuid4())

    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT incident_id, site_code, err_batch_no, error_message,
                   component_id, pipeline_status
            FROM live_incidents
            WHERE incident_id = %s
            FOR UPDATE
            """,
            (incident_id,),
        )
        incident = cursor.fetchone()
        if incident is None:
            return None
        if incident["pipeline_status"] != "VERIFIED":
            raise ValueError(
                "A remediation can only be requested for a VERIFIED incident"
            )
        _require_current_evidence(cursor, incident)

        cursor.execute(
            """
            SELECT
                action_id,
                component_id,
                target_id,
                display_name,
                risk_level,
                lifecycle_status,
                implementation_version,
                requires_approval
            FROM remediation_action_catalog
            WHERE action_id = %s
            FOR UPDATE
            """,
            (action_id,),
        )
        action = cursor.fetchone()
        if action is None:
            raise ValueError("The requested remediation action is not registered")
        if action["lifecycle_status"] != "ACTIVE":
            raise ValueError("The requested remediation action is not ACTIVE")
        if action["component_id"] != incident["component_id"]:
            raise ValueError(
                "The remediation action is not authorized for this component"
            )
        if not bool(action["requires_approval"]):
            raise ValueError(
                "This executor currently supports approval-required actions only"
            )

        try:
            cursor.execute(
                """
                INSERT INTO remediation_requests (
                    incident_id,
                    component_id_snapshot,
                    action_id,
                    target_id,
                    action_name_snapshot,
                    risk_level_snapshot,
                    implementation_version_snapshot,
                    request_reason,
                    idempotency_key,
                    requested_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    incident_id,
                    incident["component_id"],
                    action["action_id"],
                    action["target_id"],
                    action["display_name"],
                    action["risk_level"],
                    action["implementation_version"],
                    request_reason,
                    request_key,
                    requested_by,
                ),
            )
        except Exception as exc:
            if getattr(exc, "errno", None) == 1062:
                raise ValueError(
                    "An active request for this incident and action already exists"
                ) from exc
            raise

        remediation_id = cursor.lastrowid
        _insert_remediation_event(
            cursor,
            remediation_id,
            None,
            "PENDING_APPROVAL",
            "ENGINEER",
            requested_by,
            "Remediation requested; no command has been executed",
        )

    return {
        "remediation_id": remediation_id,
        "incident_id": incident_id,
        "component_id": incident["component_id"],
        "action_id": action_id,
        "target_id": action["target_id"],
        "status": "PENDING_APPROVAL",
        "idempotency_key": request_key,
        "message": "Remediation request created and awaiting approval",
    }


def approve_remediation_request(
    remediation_id: int,
    approved_by: str,
    comment: str,
) -> Optional[dict[str, Any]]:
    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT
                r.status,
                r.incident_id,
                r.action_id,
                r.implementation_version_snapshot,
                a.lifecycle_status,
                a.implementation_version
            FROM remediation_requests r
            INNER JOIN remediation_action_catalog a
                ON a.action_id = r.action_id
            WHERE r.remediation_id = %s
            FOR UPDATE
            """,
            (remediation_id,),
        )
        request = cursor.fetchone()
        if request is None:
            return None
        if request["status"] != "PENDING_APPROVAL":
            raise ValueError("Only a PENDING_APPROVAL request can be approved")
        if request["lifecycle_status"] != "ACTIVE":
            raise ValueError("The action is no longer ACTIVE")
        if (
            request["implementation_version_snapshot"]
            != request["implementation_version"]
        ):
            raise ValueError(
                "The action changed after it was requested; create a new request"
            )

        cursor.execute(
            """
            SELECT incident_id, site_code, err_batch_no,
                   error_message, pipeline_status
            FROM live_incidents
            WHERE incident_id = %s
            FOR UPDATE
            """,
            (request["incident_id"],),
        )
        incident = cursor.fetchone()
        if incident is None or incident["pipeline_status"] != "VERIFIED":
            raise ValueError("The incident is no longer VERIFIED")
        _require_current_evidence(cursor, incident)

        cursor.execute(
            """
            UPDATE remediation_requests
            SET status = 'APPROVED',
                approved_by = %s,
                approved_at = CURRENT_TIMESTAMP,
                approval_comment = %s
            WHERE remediation_id = %s
              AND status = 'PENDING_APPROVAL'
            """,
            (approved_by, comment, remediation_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Remediation status changed before approval")
        _insert_remediation_event(
            cursor,
            remediation_id,
            "PENDING_APPROVAL",
            "APPROVED",
            "ENGINEER",
            approved_by,
            comment or "Engineer approved the registered remediation",
        )

    return {
        "remediation_id": remediation_id,
        "status": "APPROVED",
        "message": "Remediation approved and available to the executor",
    }


def reject_remediation_request(
    remediation_id: int,
    rejected_by: str,
    comment: str,
) -> Optional[dict[str, Any]]:
    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT status
            FROM remediation_requests
            WHERE remediation_id = %s
            FOR UPDATE
            """,
            (remediation_id,),
        )
        request = cursor.fetchone()
        if request is None:
            return None
        if request["status"] != "PENDING_APPROVAL":
            raise ValueError("Only a PENDING_APPROVAL request can be rejected")

        cursor.execute(
            """
            UPDATE remediation_requests
            SET status = 'REJECTED',
                rejected_by = %s,
                rejected_at = CURRENT_TIMESTAMP,
                rejection_comment = %s,
                completed_at = CURRENT_TIMESTAMP
            WHERE remediation_id = %s
              AND status = 'PENDING_APPROVAL'
            """,
            (rejected_by, comment, remediation_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Remediation status changed before rejection")
        _insert_remediation_event(
            cursor,
            remediation_id,
            "PENDING_APPROVAL",
            "REJECTED",
            "ENGINEER",
            rejected_by,
            comment or "Engineer rejected the remediation",
        )

    return {
        "remediation_id": remediation_id,
        "status": "REJECTED",
        "message": "Remediation rejected; no command was executed",
    }


def resolve_manual_remediation(
    remediation_id: int,
    outcome: str,
    resolved_by: str,
    comment: str,
) -> Optional[dict[str, Any]]:
    if outcome not in {"SUCCEEDED", "FAILED", "CANCELLED"}:
        raise ValueError("Invalid manual remediation outcome")

    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT status
            FROM remediation_requests
            WHERE remediation_id = %s
            FOR UPDATE
            """,
            (remediation_id,),
        )
        request = cursor.fetchone()
        if request is None:
            return None
        if request["status"] != "MANUAL_REVIEW":
            raise ValueError("Only a MANUAL_REVIEW request can be resolved manually")

        cursor.execute(
            """
            UPDATE remediation_requests
            SET status = %s,
                manual_resolution_by = %s,
                manual_resolution_at = CURRENT_TIMESTAMP,
                manual_resolution_comment = %s,
                error_message = CASE
                    WHEN %s = 'SUCCEEDED' THEN NULL
                    ELSE %s
                END,
                completed_at = CURRENT_TIMESTAMP,
                lease_expires_at = NULL
            WHERE remediation_id = %s
              AND status = 'MANUAL_REVIEW'
            """,
            (
                outcome,
                resolved_by,
                comment,
                outcome,
                comment,
                remediation_id,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Remediation status changed during manual resolution")
        _insert_remediation_event(
            cursor,
            remediation_id,
            "MANUAL_REVIEW",
            outcome,
            "ENGINEER",
            resolved_by,
            comment,
        )

    return {
        "remediation_id": remediation_id,
        "status": outcome,
        "message": "Manual remediation outcome recorded",
    }


def list_incidents(status: Optional[str], limit: int, offset: int) -> list[dict[str, Any]]:
    where = "WHERE pipeline_status = %s" if status else ""
    parameters: list[Any] = [status] if status else []
    parameters.extend([limit, offset])
    with database_cursor() as (_, cursor):
        cursor.execute(
            f"""
            SELECT {INCIDENT_COLUMNS}
            FROM live_incidents
            {where}
            ORDER BY incident_id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(parameters),
        )
        return [_normalize_incident_record(row) for row in cursor.fetchall()]


def inject_test_batch(test_case_id: str) -> Optional[dict[str, Any]]:
    """Insert one server-owned fixture into the replicated source tables."""

    test_case = get_test_case(test_case_id)
    if test_case is None:
        return None

    batch = test_case["batch_master"]
    details = test_case["batch_details"]
    if not details:
        raise RuntimeError("The registered test batch has no detail rows")

    err_batch_no = (
        f"TEST-{test_case_id[:100]}-{uuid.uuid4().hex}"
    )

    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            INSERT INTO t_batch_master (
                site_code,
                err_batch_no,
                proj_name,
                dag_id,
                batch_start_date,
                min_severity,
                alert_status,
                source_modified,
                replicated_date
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """,
            (
                batch["site_code"],
                err_batch_no,
                batch["proj_name"],
                batch["dag_id"],
                batch["batch_start_date"],
                batch["min_severity"],
                batch["alert_status"],
            ),
        )

        for detail in details:
            cursor.execute(
                """
                INSERT INTO t_batch_detail (
                    site_code,
                    err_batch_no,
                    dag_id,
                    dag_startdate,
                    dag_enddate,
                    category,
                    severity,
                    message,
                    exception_type,
                    status
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    batch["site_code"],
                    err_batch_no,
                    detail.get("dag_id") or batch["dag_id"],
                    detail.get("dag_startdate")
                    or batch["batch_start_date"],
                    detail.get("dag_enddate")
                    or batch["batch_start_date"],
                    detail.get("category"),
                    detail.get("severity"),
                    detail.get("message"),
                    detail.get("exception_type"),
                    detail.get("status"),
                ),
            )

    return {
        "test_case_id": test_case_id,
        "site_code": batch["site_code"],
        "err_batch_no": err_batch_no,
        "component_id": batch["dag_id"],
        "alert_status": batch["alert_status"],
        "detail_count": len(details),
        "expected_distinct_error_count": test_case[
            "expected_distinct_error_count"
        ],
        "message": (
            "Test source batch inserted; the batch importer will create its "
            "live incident"
        ),
    }


def get_incident(incident_id: int) -> Optional[dict[str, Any]]:
    with database_cursor() as (_, cursor):
        cursor.execute(
            f"SELECT {INCIDENT_DETAIL_COLUMNS} FROM live_incidents WHERE incident_id = %s",
            (incident_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        cursor.execute(
            """
            SELECT investigation_sop
            FROM t_sops_master
            WHERE DAG_id = %s
            LIMIT 1
            """,
            (row["component_id"],),
        )
        sop_row = cursor.fetchone()

        cursor.execute(
            """
            SELECT review_id, decision, final_root_cause, selected_actions, comment,
                   reviewed_by, reviewed_at, promoted_to_knowledge_base,
                   promoted_by, promoted_at, knowledge_base_id,
                   rca_id,
                   last_edited_by, last_edited_at
            FROM incident_reviews
            WHERE incident_id = %s
            ORDER BY review_id DESC
            LIMIT 1
            """,
            (incident_id,),
        )
        review = cursor.fetchone()
        evidence_state = _source_evidence_state(cursor, row)

    result = _normalize_incident_record(row)
    result["investigation_sop"] = (
        sop_row["investigation_sop"] if sop_row else ""
    )
    result["latest_review"] = normalize_review(review) if review else None
    result.update(evidence_state)
    analysis_current = _analysis_snapshot_current(row, evidence_state)
    result["analysis_evidence_current"] = analysis_current
    assessment = result.get("final_assessment")
    verifier = result.get("verifier_findings")
    ai_answer_eligible = (
        analysis_current
        and isinstance(assessment, dict)
        and isinstance(verifier, dict)
        and verifier.get("evidence_complete") is True
        and assessment.get("proposal_assessment") == "SUPPORTED"
        and assessment.get("can_use_all_ai_answers") is True
        and bool(str(assessment.get("final_root_cause") or "").strip())
    )
    result["ai_answer_eligible"] = ai_answer_eligible
    if isinstance(assessment, dict):
        result["final_assessment"] = {
            **assessment,
            "can_use_all_ai_answers": ai_answer_eligible,
        }
    return result


def get_incident_by_batch(
    site_code: str,
    err_batch_no: str,
) -> Optional[dict[str, Any]]:
    """Resolve the external batch identity to the full incident response."""

    normalized_site_code = str(site_code or "").strip().upper()
    normalized_batch_number = str(err_batch_no or "").strip()
    if not normalized_site_code or not normalized_batch_number:
        return None

    with database_cursor() as (_, cursor):
        cursor.execute(
            """
            SELECT incident_id
            FROM live_incidents
            WHERE site_code = %s AND err_batch_no = %s
            ORDER BY incident_id DESC
            LIMIT 1
            """,
            (normalized_site_code, normalized_batch_number),
        )
        row = cursor.fetchone()

    return get_incident(int(row["incident_id"])) if row else None


def list_closed_reviews(limit: int, offset: int) -> list[dict[str, Any]]:
    """Returns engineer-reviewed incidents for the read-only closed archive."""

    with database_cursor() as (_, cursor):
        cursor.execute(
            """
            SELECT
                r.review_id,
                r.incident_id,
                i.source_system,
                i.component_id,
                i.exception_type,
                i.error_message,
                r.decision,
                r.final_root_cause,
                r.selected_actions,
                r.comment,
                r.reviewed_by,
                r.reviewed_at,
                r.promoted_to_knowledge_base,
                r.promoted_by,
                r.promoted_at,
                r.knowledge_base_id,
                r.rca_id,
                r.last_edited_by,
                r.last_edited_at
            FROM incident_reviews r
            INNER JOIN live_incidents i
                ON i.incident_id = r.incident_id
            WHERE i.pipeline_status = 'CLOSED'
            ORDER BY COALESCE(r.last_edited_at, r.reviewed_at) DESC, r.review_id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        rows = cursor.fetchall()

    return [normalize_review(row) for row in rows]


def dashboard_metrics() -> dict[str, Any]:
    with database_cursor() as (_, cursor):
        cursor.execute(
            """
            SELECT pipeline_status, COUNT(*) AS total
            FROM live_incidents
            GROUP BY pipeline_status
            """
        )
        counts = {row["pipeline_status"]: row["total"] for row in cursor.fetchall()}

    total = sum(counts.values())
    verified = counts.get("VERIFIED", 0)
    closed = counts.get("CLOSED", 0)
    return {
        "total_incidents": total,
        "verified_incidents": verified,
        "closed_incidents": closed,
        "errors": counts.get("ERROR", 0),
        "active_incidents": sum(
            counts.get(status, 0)
            for status in ("NEW", "ANALYZING", "AWAITING_VERIFICATION")
        ),
        "verified_rate": round(((verified + closed) / total) * 100, 1) if total else 0,
        "by_status": counts,
    }


def _analytics_date(value: Any) -> Optional[str]:
    """Return a stable ISO date for database date/datetime/string values."""

    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()

    text = str(value).strip()
    return text[:10] if text else None


def analytics_overview(days: int = 30, limit: int = 10) -> dict[str, Any]:
    """Aggregate incident and raw-error activity for the Analytics page.

    Incident-level charts count rows from ``live_incidents`` so a source batch
    is counted once. Error-pattern charts intentionally count matching
    ``t_batch_detail`` rows and also expose their distinct source-batch count.
    """

    end_date = date.today()
    start_date = end_date - timedelta(days=days - 1)
    exclusive_end_date = end_date + timedelta(days=1)

    with database_cursor() as (_, cursor):
        cursor.execute(
            """
            SELECT
                COUNT(*) AS incident_count,
                COUNT(DISTINCT NULLIF(TRIM(li.component_id), ''))
                    AS affected_dag_count,
                COUNT(DISTINCT NULLIF(TRIM(bm.proj_name), ''))
                    AS affected_project_count,
                COUNT(DISTINCT NULLIF(TRIM(li.site_code), ''))
                    AS affected_site_count
            FROM live_incidents li
            LEFT JOIN t_batch_master bm
              ON bm.site_code = li.site_code
             AND bm.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            """,
            (start_date, exclusive_end_date),
        )
        incident_summary = cursor.fetchone() or {}

        cursor.execute(
            """
            SELECT
                COUNT(*) AS raw_error_count,
                COUNT(
                    DISTINCT CONCAT_WS(
                        CHAR(31),
                        COALESCE(NULLIF(TRIM(bd.dag_id), ''), ''),
                        COALESCE(NULLIF(TRIM(bd.category), ''), ''),
                        COALESCE(NULLIF(TRIM(bd.exception_type), ''), ''),
                        COALESCE(NULLIF(TRIM(bd.message), ''), '')
                    )
                ) AS distinct_error_pattern_count
            FROM live_incidents li
            INNER JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            """,
            (start_date, exclusive_end_date),
        )
        error_summary = cursor.fetchone() or {}

        cursor.execute(
            """
            SELECT
                COALESCE(
                    NULLIF(TRIM(bd.dag_id), ''),
                    NULLIF(TRIM(li.component_id), ''),
                    'Unknown DAG'
                ) AS dag_id,
                COALESCE(
                    NULLIF(TRIM(bd.category), ''),
                    'Uncategorized'
                ) AS category,
                COALESCE(
                    NULLIF(TRIM(bd.exception_type), ''),
                    'Unknown exception'
                ) AS exception_type,
                COALESCE(
                    NULLIF(TRIM(bd.message), ''),
                    'No error message'
                ) AS message,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT li.incident_id) AS batch_count,
                COUNT(DISTINCT bd.site_code) AS affected_site_count,
                MAX(li.incident_time) AS last_seen
            FROM live_incidents li
            INNER JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            GROUP BY
                COALESCE(
                    NULLIF(TRIM(bd.dag_id), ''),
                    NULLIF(TRIM(li.component_id), ''),
                    'Unknown DAG'
                ),
                COALESCE(
                    NULLIF(TRIM(bd.category), ''),
                    'Uncategorized'
                ),
                COALESCE(
                    NULLIF(TRIM(bd.exception_type), ''),
                    'Unknown exception'
                ),
                COALESCE(
                    NULLIF(TRIM(bd.message), ''),
                    'No error message'
                )
            ORDER BY batch_count DESC, occurrence_count DESC, last_seen DESC
            LIMIT %s
            """,
            (start_date, exclusive_end_date, limit),
        )
        top_error_patterns = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                COALESCE(
                    NULLIF(TRIM(bd.exception_type), ''),
                    'Unknown exception'
                ) AS exception_type,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT li.incident_id) AS batch_count,
                COUNT(DISTINCT bd.site_code) AS affected_site_count,
                COUNT(
                    DISTINCT COALESCE(
                        NULLIF(TRIM(bd.dag_id), ''),
                        NULLIF(TRIM(li.component_id), ''),
                        'Unknown DAG'
                    )
                ) AS affected_dag_count,
                MAX(li.incident_time) AS last_seen
            FROM live_incidents li
            INNER JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            GROUP BY COALESCE(
                NULLIF(TRIM(bd.exception_type), ''),
                'Unknown exception'
            )
            ORDER BY batch_count DESC, occurrence_count DESC, exception_type
            """,
            (start_date, exclusive_end_date),
        )
        exception_types = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                DATE(li.incident_time) AS activity_date,
                COUNT(DISTINCT li.incident_id) AS incident_count,
                COUNT(bd.row_id) AS raw_error_count
            FROM live_incidents li
            LEFT JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            GROUP BY DATE(li.incident_time)
            ORDER BY activity_date
            """,
            (start_date, exclusive_end_date),
        )
        trend_rows = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                COALESCE(
                    NULLIF(TRIM(li.component_id), ''),
                    'Unknown DAG'
                ) AS name,
                COUNT(DISTINCT li.incident_id) AS incident_count,
                COUNT(bd.row_id) AS raw_error_count,
                COUNT(DISTINCT li.site_code) AS affected_site_count
            FROM live_incidents li
            LEFT JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            GROUP BY COALESCE(
                NULLIF(TRIM(li.component_id), ''),
                'Unknown DAG'
            )
            ORDER BY incident_count DESC, raw_error_count DESC, name
            LIMIT %s
            """,
            (start_date, exclusive_end_date, limit),
        )
        affected_dags = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                COALESCE(
                    NULLIF(TRIM(bm.proj_name), ''),
                    'Unassigned project'
                ) AS name,
                COUNT(DISTINCT li.incident_id) AS incident_count,
                COUNT(bd.row_id) AS raw_error_count,
                COUNT(DISTINCT NULLIF(TRIM(li.component_id), ''))
                    AS affected_dag_count
            FROM live_incidents li
            LEFT JOIN t_batch_master bm
              ON bm.site_code = li.site_code
             AND bm.err_batch_no = li.err_batch_no
            LEFT JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            GROUP BY COALESCE(
                NULLIF(TRIM(bm.proj_name), ''),
                'Unassigned project'
            )
            ORDER BY incident_count DESC, raw_error_count DESC, name
            LIMIT %s
            """,
            (start_date, exclusive_end_date, limit),
        )
        projects = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                COALESCE(
                    NULLIF(TRIM(li.site_code), ''),
                    'Unknown site'
                ) AS name,
                COUNT(DISTINCT li.incident_id) AS incident_count,
                COUNT(bd.row_id) AS raw_error_count,
                COUNT(DISTINCT NULLIF(TRIM(li.component_id), ''))
                    AS affected_dag_count
            FROM live_incidents li
            LEFT JOIN t_batch_detail bd
              ON bd.site_code = li.site_code
             AND bd.err_batch_no = li.err_batch_no
            WHERE li.incident_time >= %s
              AND li.incident_time < %s
            GROUP BY COALESCE(
                NULLIF(TRIM(li.site_code), ''),
                'Unknown site'
            )
            ORDER BY incident_count DESC, raw_error_count DESC, name
            LIMIT %s
            """,
            (start_date, exclusive_end_date, limit),
        )
        sites = cursor.fetchall()

    trend_by_date = {
        _analytics_date(row.get("activity_date")): row
        for row in trend_rows
        if _analytics_date(row.get("activity_date"))
    }
    daily_trend: list[dict[str, Any]] = []
    for offset in range(days):
        current_date = start_date + timedelta(days=offset)
        iso_date = current_date.isoformat()
        row = trend_by_date.get(iso_date, {})
        daily_trend.append(
            {
                "date": iso_date,
                "incident_count": int(row.get("incident_count") or 0),
                "raw_error_count": int(row.get("raw_error_count") or 0),
            }
        )

    summary = {
        "incident_count": int(incident_summary.get("incident_count") or 0),
        "raw_error_count": int(error_summary.get("raw_error_count") or 0),
        "distinct_error_pattern_count": int(
            error_summary.get("distinct_error_pattern_count") or 0
        ),
        "affected_dag_count": int(
            incident_summary.get("affected_dag_count") or 0
        ),
        "affected_project_count": int(
            incident_summary.get("affected_project_count") or 0
        ),
        "affected_site_count": int(
            incident_summary.get("affected_site_count") or 0
        ),
    }

    return {
        "window": {
            "days": days,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        },
        "summary": summary,
        "exception_types": exception_types,
        "top_error_patterns": top_error_patterns,
        "daily_trend": daily_trend,
        "affected_dags": affected_dags,
        "projects": projects,
        "sites": sites,
    }


def create_review(
    incident_id: int,
    decision: str,
    final_root_cause: str,
    selected_actions: list[str],
    comment: str,
    reviewer: str,
    promote_to_knowledge_base: bool = False,
) -> Optional[dict[str, Any]]:
    normalized_actions = _normalized_actions(selected_actions)
    _validate_promotion(
        decision,
        normalized_actions,
        promote_to_knowledge_base,
    )

    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT
                incident_id,
                site_code,
                err_batch_no,
                source_system,
                component_id,
                exception_type,
                error_message,
                ai_proposed_root_cause,
                pipeline_status
            FROM live_incidents
            WHERE incident_id = %s
            FOR UPDATE
            """,
            (incident_id,),
        )
        incident = cursor.fetchone()
        if incident is None:
            return None
        if incident["pipeline_status"] != "VERIFIED":
            raise ValueError("Only VERIFIED incidents can receive an engineer decision")
        _require_current_evidence(cursor, incident)

        cursor.execute(
            """
            INSERT INTO incident_reviews (
                incident_id, decision, final_root_cause, selected_actions,
                comment, reviewed_by, promoted_to_knowledge_base,
                knowledge_base_id, rca_id
            ) VALUES (%s, %s, %s, %s, %s, %s, FALSE, NULL, NULL)
            """,
            (
                incident_id,
                decision,
                final_root_cause,
                json.dumps(normalized_actions),
                comment,
                reviewer,
            ),
        )
        review_id = cursor.lastrowid
        rca_id = None

        if promote_to_knowledge_base:
            rca_id = _insert_rca_master(
                cursor,
                incident,
                decision,
                final_root_cause,
                normalized_actions,
                reviewer,
            )
            _ensure_rca_mapping(cursor, incident, rca_id, reviewer)
            cursor.execute(
                """
                UPDATE incident_reviews
                SET promoted_to_knowledge_base = TRUE,
                    promoted_by = %s,
                    promoted_at = CURRENT_TIMESTAMP,
                    rca_id = %s
                WHERE review_id = %s
                """,
                (reviewer, rca_id, review_id),
            )

        _sync_operational_resolution(
            cursor,
            incident,
            final_root_cause,
            normalized_actions,
            reviewer,
        )

    return {
        "review_id": review_id,
        "rca_id": rca_id,
        "pipeline_status": "CLOSED",
        "knowledge_base_promoted": promote_to_knowledge_base,
        "message": "Engineer decision recorded and incident closed",
    }


def update_closed_review(
    review_id: int,
    decision: str,
    final_root_cause: str,
    selected_actions: list[str],
    comment: str,
    editor: str,
    promote_to_knowledge_base: bool = False,
) -> Optional[dict[str, Any]]:
    """Updates a closed review without creating a duplicate review row."""

    normalized_actions = _normalized_actions(selected_actions)
    _validate_promotion(
        decision,
        normalized_actions,
        promote_to_knowledge_base,
    )

    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT
                r.review_id,
                r.incident_id,
                r.decision AS previous_decision,
                r.final_root_cause AS previous_root_cause,
                r.selected_actions AS previous_actions,
                r.promoted_to_knowledge_base,
                r.knowledge_base_id,
                r.rca_id,
                i.site_code,
                i.err_batch_no,
                i.source_system,
                i.component_id,
                i.exception_type,
                i.error_message,
                i.ai_proposed_root_cause,
                i.pipeline_status
            FROM incident_reviews r
            INNER JOIN live_incidents i
                ON i.incident_id = r.incident_id
            WHERE r.review_id = %s
            FOR UPDATE
            """,
            (review_id,),
        )
        existing = cursor.fetchone()
        if existing is None:
            return None
        if existing["pipeline_status"] != "CLOSED":
            raise ValueError("Only CLOSED incident reviews can be edited")
        _require_current_evidence(cursor, existing)

        already_promoted = bool(existing["promoted_to_knowledge_base"])
        rca_id = existing.get("rca_id")
        previous_actions = _normalized_actions(
            normalize_review(
                {"selected_actions": existing.get("previous_actions")}
            )["selected_actions"]
        )
        resolution_changed = (
            str(existing.get("previous_root_cause") or "").strip()
            != final_root_cause.strip()
            or previous_actions != normalized_actions
        )
        knowledge_changed = (
            resolution_changed
            or existing.get("previous_decision") != decision
        )

        if already_promoted:
            if not promote_to_knowledge_base:
                raise ValueError("A promoted resolution cannot be unpromoted by editing it")
            if decision == "rejected":
                raise ValueError("A promoted resolution cannot be changed to rejected")
            if rca_id is None:
                raise ValueError(
                    "This promoted review has no t_rca_master link. "
                    "Set its rca_id before editing the resolution."
                )
            if knowledge_changed:
                _update_rca_master(
                    cursor,
                    int(rca_id),
                    existing,
                    decision,
                    final_root_cause,
                    normalized_actions,
                )

        elif promote_to_knowledge_base:
            rca_id = _insert_rca_master(
                cursor,
                existing,
                decision,
                final_root_cause,
                normalized_actions,
                editor,
            )
            _ensure_rca_mapping(cursor, existing, rca_id, editor)

        cursor.execute(
            """
            UPDATE incident_reviews
            SET decision = %s,
                final_root_cause = %s,
                selected_actions = %s,
                comment = %s,
                last_edited_by = %s,
                last_edited_at = CURRENT_TIMESTAMP,
                promoted_to_knowledge_base = %s,
                promoted_by = CASE
                    WHEN %s = TRUE AND promoted_by IS NULL THEN %s
                    ELSE promoted_by
                END,
                promoted_at = CASE
                    WHEN %s = TRUE AND promoted_at IS NULL THEN CURRENT_TIMESTAMP
                    ELSE promoted_at
                END,
                rca_id = %s
            WHERE review_id = %s
            """,
            (
                decision,
                final_root_cause,
                json.dumps(normalized_actions),
                comment,
                editor,
                promote_to_knowledge_base,
                promote_to_knowledge_base,
                editor,
                promote_to_knowledge_base,
                rca_id,
                review_id,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("The closed review changed before the edit could be saved")

        if resolution_changed:
            _sync_operational_resolution(
                cursor,
                existing,
                final_root_cause,
                normalized_actions,
                editor,
            )

    return {
        "review_id": review_id,
        "rca_id": rca_id,
        "pipeline_status": "CLOSED",
        "knowledge_base_promoted": promote_to_knowledge_base,
        "knowledge_base_updated": already_promoted,
        "message": (
            "Closed resolution and linked knowledge-base entry updated"
            if already_promoted
            else (
                "Closed resolution updated and promoted to the knowledge base"
                if promote_to_knowledge_base
                else "Closed resolution updated"
            )
        ),
    }


def promote_closed_review(
    review_id: int,
    reviewer: str,
) -> Optional[dict[str, Any]]:
    """Promotes one eligible, engineer-confirmed closed review exactly once."""

    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT
                r.review_id,
                r.decision,
                r.final_root_cause,
                r.selected_actions,
                r.promoted_to_knowledge_base,
                r.rca_id,
                i.incident_id,
                i.site_code,
                i.err_batch_no,
                i.source_system,
                i.component_id,
                i.exception_type,
                i.error_message,
                i.ai_proposed_root_cause,
                i.pipeline_status
            FROM incident_reviews r
            INNER JOIN live_incidents i
                ON i.incident_id = r.incident_id
            WHERE r.review_id = %s
            FOR UPDATE
            """,
            (review_id,),
        )
        review = cursor.fetchone()
        if review is None:
            return None
        if review["pipeline_status"] != "CLOSED":
            raise ValueError("Only CLOSED incidents can be promoted")
        _require_current_evidence(cursor, review)
        if review["decision"] == "rejected":
            raise ValueError("A rejected resolution cannot be promoted")
        if bool(review["promoted_to_knowledge_base"]):
            return {
                "review_id": review_id,
                "knowledge_base_promoted": True,
                "already_promoted": True,
                "message": "This resolution was already promoted",
            }

        normalized_review = normalize_review(review)
        actions = _normalized_actions(normalized_review["selected_actions"])
        if not actions:
            raise ValueError("Add at least one confirmed action before promotion")

        rca_id = _insert_rca_master(
            cursor,
            review,
            review["decision"],
            review["final_root_cause"],
            actions,
            reviewer,
        )
        _ensure_rca_mapping(cursor, review, rca_id, reviewer)
        cursor.execute(
            """
            UPDATE incident_reviews
            SET promoted_to_knowledge_base = TRUE,
                promoted_by = %s,
                promoted_at = CURRENT_TIMESTAMP,
                rca_id = %s
            WHERE review_id = %s
              AND promoted_to_knowledge_base = FALSE
            """,
            (reviewer, rca_id, review_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Review promotion state changed before it could be saved")

    return {
        "review_id": review_id,
        "rca_id": rca_id,
        "knowledge_base_promoted": True,
        "already_promoted": False,
        "message": "Engineer-confirmed resolution promoted to the knowledge base",
    }


def list_sops() -> list[dict[str, Any]]:
    with database_cursor() as (_, cursor):
        cursor.execute(
            """
            SELECT s.DAG_id, s.investigation_sop,
                   (
                       SELECT COUNT(*)
                       FROM live_incidents i
                       WHERE i.component_id = s.DAG_id
                   ) AS incident_count
            FROM t_sops_master s
            ORDER BY s.DAG_id
            """
        )
        rows = cursor.fetchall()
    return [
        {
            "dag_id": row["DAG_id"],
            "investigation_sop": row["investigation_sop"] or "",
            "content_hash": sha256_text(row["investigation_sop"] or ""),
            "incident_count": row["incident_count"],
        }
        for row in rows
    ]


def get_sop(dag_id: str) -> Optional[dict[str, Any]]:
    with database_cursor() as (_, cursor):
        cursor.execute(
            """
            SELECT DAG_id, investigation_sop
            FROM t_sops_master
            WHERE DAG_id = %s
            LIMIT 1
            """,
            (dag_id,),
        )
        row = cursor.fetchone()
    if row is None:
        return None
    content = row["investigation_sop"] or ""
    return {
        "dag_id": row["DAG_id"],
        "investigation_sop": content,
        "content_hash": sha256_text(content),
    }


def update_sop(
    dag_id: str,
    investigation_sop: str,
    expected_hash: str,
    change_note: str,
    updated_by: str,
) -> Optional[dict[str, Any]]:
    with database_cursor(commit=True) as (_, cursor):
        cursor.execute(
            """
            SELECT investigation_sop
            FROM t_sops_master
            WHERE DAG_id = %s
            FOR UPDATE
            """,
            (dag_id,),
        )
        current = cursor.fetchone()
        if current is None:
            return None

        old_content = current["investigation_sop"] or ""
        old_hash = sha256_text(old_content)
        if old_hash != expected_hash:
            raise RuntimeError("SOP_CHANGED")

        cursor.execute(
            """
            INSERT INTO sop_revisions (
                DAG_id, previous_sop, previous_hash, change_note, changed_by
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (dag_id, old_content, old_hash, change_note, updated_by),
        )
        cursor.execute(
            """
            UPDATE t_sops_master
            SET investigation_sop = %s
            WHERE DAG_id = %s
            """,
            (investigation_sop, dag_id),
        )

    return {
        "dag_id": dag_id,
        "investigation_sop": investigation_sop,
        "content_hash": sha256_text(investigation_sop),
    }
