"""Import replicated alert batches into the internal incident workflow."""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

import mysql.connector
from dotenv import load_dotenv


load_dotenv(Path(__file__).with_name(".env"))

LOGGER = logging.getLogger("rca.batch_importer")
ACTIVE_ALERT_STATUSES = ("OPEN", "RESOLVED")
MAX_ERROR_MESSAGE_BYTES = 16_000_000
REFRESH_LATE_DETAILS = os.getenv(
    "BATCH_IMPORTER_REFRESH_LATE_DETAILS", "false"
).strip().lower() in {"1", "true", "yes"}


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is missing")
    return value


@dataclass(frozen=True)
class BatchImporterSettings:
    db_host: str
    db_port: int
    db_user: str
    db_password: str
    db_name: str
    poll_seconds: int
    batch_size: int

    @classmethod
    def from_environment(cls) -> "BatchImporterSettings":
        poll_seconds = int(os.getenv("BATCH_IMPORTER_POLL_SECONDS", "15"))
        batch_size = int(os.getenv("BATCH_IMPORTER_BATCH_SIZE", "100"))
        if poll_seconds < 1:
            raise RuntimeError("BATCH_IMPORTER_POLL_SECONDS must be at least 1")
        if not 1 <= batch_size <= 1000:
            raise RuntimeError(
                "BATCH_IMPORTER_BATCH_SIZE must be between 1 and 1000"
            )

        return cls(
            db_host=_required("DB_HOST"),
            db_port=int(os.getenv("DB_PORT", "3306")),
            db_user=_required("DB_USER"),
            db_password=_required("DB_PASSWORD"),
            db_name=_required("DB_NAME"),
            poll_seconds=poll_seconds,
            batch_size=batch_size,
        )


def _json_default(value: Any) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _append_unique(values: list[Any], value: Any) -> None:
    """Append a non-null value once while preserving its first-seen order."""

    if value is not None and value not in values:
        values.append(value)


def group_similar_errors(
    details: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Group duplicate batch details into deterministic diagnostic units.

    A group is identified by the exact DAG ID, category, exception type and
    message after removing surrounding whitespace. Severity and row status do
    not split a group; their distinct values remain available as metadata.

    This intentionally does not use fuzzy or LLM-based similarity. Diagnostic
    checks must not silently combine messages that only appear related.
    """

    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for detail in details:
        dag_id = _clean_text(detail.get("dag_id"))
        category = _clean_text(detail.get("category"))
        exception_type = _clean_text(detail.get("exception_type"))
        message = _clean_text(detail.get("message"))
        signature = (dag_id, category, exception_type, message)

        group = grouped.get(signature)
        if group is None:
            group = {
                "group_id": f"error_group_{len(grouped) + 1}",
                "dag_id": dag_id or None,
                "category": category or None,
                "exception_type": exception_type or None,
                "message": message or None,
                "occurrence_count": 0,
                "row_ids": [],
                "severities": [],
                "statuses": [],
            }
            grouped[signature] = group

        group["occurrence_count"] += 1
        _append_unique(group["row_ids"], detail.get("row_id"))
        _append_unique(group["severities"], detail.get("severity"))

        status = _clean_text(detail.get("status"))
        _append_unique(group["statuses"], status or None)

    return list(grouped.values())


def _exception_summary(details: list[dict[str, Any]]) -> Optional[str]:
    exception_types: list[str] = []
    for detail in details:
        value = _clean_text(detail.get("exception_type"))
        if value and value not in exception_types:
            exception_types.append(value)

    if not exception_types:
        return None

    summary = ", ".join(exception_types)
    return summary if len(summary) <= 255 else summary[:252] + "..."


def _severity(batch: dict[str, Any], details: list[dict[str, Any]]) -> Optional[int]:
    values = [
        int(detail["severity"])
        for detail in details
        if detail.get("severity") is not None
    ]
    if batch.get("min_severity") is not None:
        values.append(int(batch["min_severity"]))
    return min(values) if values else None


def format_batch_error_message(
    batch: dict[str, Any],
    details: list[dict[str, Any]],
) -> str:
    """Create grouped diagnostic evidence while preserving every source row."""

    distinct_error_groups = group_similar_errors(details)

    payload = {
        "schema_version": 1,
        "site_code": batch["site_code"],
        "err_batch_no": batch["err_batch_no"],
        "project_name": batch.get("proj_name"),
        "dag_id": batch.get("dag_id"),
        "batch_start_date": batch.get("batch_start_date"),
        "alert_status": batch.get("alert_status"),
        "detail_count": len(details),
        "distinct_error_count": len(distinct_error_groups),
        "distinct_error_groups": distinct_error_groups,
        "details": [
            {
                "row_id": detail.get("row_id"),
                "dag_id": detail.get("dag_id"),
                "dag_startdate": detail.get("dag_startdate"),
                "dag_enddate": detail.get("dag_enddate"),
                "category": detail.get("category"),
                "severity": detail.get("severity"),
                "exception_type": detail.get("exception_type"),
                "status": detail.get("status"),
                "message": detail.get("message"),
            }
            for detail in details
        ],
    }
    formatted = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        default=_json_default,
    )
    if len(formatted.encode("utf-8")) > MAX_ERROR_MESSAGE_BYTES:
        raise ValueError(
            "The formatted batch evidence exceeds the live_incidents MEDIUMTEXT limit"
        )
    return formatted


def _snapshot_row_ids(error_message: Any) -> set[int]:
    """Read source IDs from the immutable evidence used by prior analysis."""

    try:
        payload = json.loads(str(error_message or ""))
        rows = payload["details"]
        if not isinstance(rows, list):
            raise ValueError("details is not a list")
        return {int(row["row_id"]) for row in rows}
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Existing incident evidence has no usable row IDs") from exc


class BatchImporter:
    def __init__(self, settings: BatchImporterSettings):
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
            use_pure=True
        )

    @staticmethod
    def _load_details(cursor: Any, batch: dict[str, Any]) -> list[dict[str, Any]]:
        cursor.execute(
            """
            SELECT
                row_id,
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
            FROM t_batch_detail
            WHERE site_code = %s
              AND err_batch_no = %s
            ORDER BY row_id
            """,
            (batch["site_code"], batch["err_batch_no"]),
        )
        return cursor.fetchall()

    def import_new_batches(self) -> int:
        """Import new batches and safely requeue eligible appended evidence.

        The late-details path requires the migration and approval/executor
        evidence guards. It is disabled until all parts are deployed.
        """

        connection = self._connect()
        cursor = connection.cursor(dictionary=True)
        changed = 0
        try:
            cursor.execute(
                """
                SELECT
                    bm.site_code,
                    bm.err_batch_no,
                    bm.proj_name,
                    bm.dag_id,
                    bm.batch_start_date,
                    bm.min_severity,
                    bm.alert_status,
                    bm.replicated_date,
                    li.incident_id,
                    li.pipeline_status
                FROM t_batch_master bm
                LEFT JOIN live_incidents li
                  ON li.site_code = bm.site_code
                 AND li.err_batch_no = bm.err_batch_no
                WHERE bm.alert_status IN (%s, %s)
                  AND bm.dag_id IS NOT NULL
                  AND TRIM(bm.dag_id) <> ''
                  AND (
                      li.incident_id IS NULL
                      OR (
                          %s = 1
                          AND li.pipeline_status IN ('NEW', 'VERIFIED', 'ERROR')
                          AND NOT EXISTS (
                              SELECT 1 FROM remediation_requests r
                              WHERE r.incident_id = li.incident_id
                          )
                          AND NOT EXISTS (
                              SELECT 1 FROM incident_reviews ir
                              WHERE ir.incident_id = li.incident_id
                          )
                      )
                  )
                  AND EXISTS (
                      SELECT 1 FROM t_batch_detail bd
                      WHERE bd.site_code = bm.site_code
                        AND bd.err_batch_no = bm.err_batch_no
                        AND (
                            li.incident_id IS NULL
                            OR bd.row_id > COALESCE(
                                li.last_imported_detail_row_id, 0
                            )
                        )
                  )
                ORDER BY
                    CASE WHEN li.incident_id IS NULL THEN 0 ELSE 1 END,
                    COALESCE(bm.replicated_date, bm.batch_start_date),
                    bm.site_code,
                    bm.err_batch_no
                LIMIT %s
                """,
                (
                    ACTIVE_ALERT_STATUSES[0],
                    ACTIVE_ALERT_STATUSES[1],
                    int(REFRESH_LATE_DETAILS),
                    self.settings.batch_size,
                ),
            )
            batches = cursor.fetchall()

            for batch in batches:
                details = self._load_details(cursor, batch)
                if not details:
                    LOGGER.warning(
                        "Skipping batch %s/%s because its detail rows are unavailable",
                        batch["site_code"],
                        batch["err_batch_no"],
                    )
                    continue

                row_ids = {int(detail["row_id"]) for detail in details}
                latest_row_id = max(row_ids)
                error_message = format_batch_error_message(batch, details)

                if batch["incident_id"] is None:
                    cursor.execute(
                        """
                        INSERT INTO live_incidents (
                            site_code, err_batch_no, source_system,
                            component_id, incident_time, exception_type,
                            error_message, severity, pipeline_status,
                            last_imported_detail_row_id
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'NEW', %s)
                        ON DUPLICATE KEY UPDATE incident_id = incident_id
                        """,
                        (
                            batch["site_code"],
                            batch["err_batch_no"],
                            batch["site_code"],
                            batch["dag_id"],
                            batch.get("batch_start_date"),
                            _exception_summary(details),
                            error_message,
                            _severity(batch, details),
                            latest_row_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        continue
                    changed += 1
                    LOGGER.info(
                        "Imported batch %s/%s as a NEW incident with %d detail "
                        "row(s) in %d distinct error group(s)",
                        batch["site_code"],
                        batch["err_batch_no"],
                        len(details),
                        len(group_similar_errors(details)),
                    )

                    continue

                # Lock the incident as the API does when creating a request.
                # In-flight and reviewed cases are deferred without changing
                # either the evidence or an engineer's prior decision.
                cursor.execute(
                    """
                    SELECT incident_id, pipeline_status, error_message,
                           last_imported_detail_row_id,
                           ai_proposed_root_cause, ai_proposed_fix,
                           ai_verifier_result, ai_verifier_findings,
                           ai_final_assessment
                    FROM live_incidents
                    WHERE incident_id = %s
                    FOR UPDATE
                    """,
                    (batch["incident_id"],),
                )
                incident = cursor.fetchone()
                if not incident or incident["pipeline_status"] not in {
                    "NEW", "VERIFIED", "ERROR"
                }:
                    continue

                cursor.execute(
                    "SELECT remediation_id FROM remediation_requests "
                    "WHERE incident_id = %s LIMIT 1",
                    (incident["incident_id"],),
                )
                if cursor.fetchone():
                    continue
                cursor.execute(
                    "SELECT review_id FROM incident_reviews "
                    "WHERE incident_id = %s LIMIT 1",
                    (incident["incident_id"],),
                )
                if cursor.fetchone():
                    continue

                try:
                    prior_ids = _snapshot_row_ids(incident["error_message"])
                except ValueError:
                    LOGGER.exception(
                        "Cannot refresh incident %s with unreadable evidence",
                        incident["incident_id"],
                    )
                    continue

                if not prior_ids.issubset(row_ids):
                    LOGGER.warning(
                        "Source details disappeared for incident %s; "
                        "leaving prior analysis intact",
                        incident["incident_id"],
                    )
                    continue

                if prior_ids == row_ids:
                    # Backfill the watermark on incidents imported before the
                    # migration; this does not alter the analysis snapshot.
                    cursor.execute(
                        "UPDATE live_incidents "
                        "SET last_imported_detail_row_id = %s "
                        "WHERE incident_id = %s",
                        (latest_row_id, incident["incident_id"]),
                    )
                    continue

                cursor.execute(
                    """
                    INSERT INTO incident_evidence_history (
                        incident_id, previous_pipeline_status,
                        previous_error_message, previous_proposal,
                        previous_fix, previous_verifier_result,
                        previous_verifier_findings,
                        previous_final_assessment,
                        previous_max_row_id, new_max_row_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        incident["incident_id"],
                        incident["pipeline_status"],
                        incident["error_message"],
                        incident["ai_proposed_root_cause"],
                        incident["ai_proposed_fix"],
                        incident["ai_verifier_result"],
                        incident["ai_verifier_findings"],
                        incident["ai_final_assessment"],
                        incident["last_imported_detail_row_id"],
                        latest_row_id,
                    ),
                )
                cursor.execute(
                    """
                    UPDATE live_incidents
                    SET error_message = %s,
                        exception_type = %s,
                        severity = %s,
                        last_imported_detail_row_id = %s,
                        pipeline_status = 'NEW',
                        ai_proposed_root_cause = NULL,
                        ai_proposed_fix = NULL,
                        ai_verifier_result = NULL,
                        ai_verifier_findings = NULL,
                        ai_final_assessment = NULL
                    WHERE incident_id = %s
                      AND pipeline_status = %s
                    """,
                    (
                        error_message,
                        _exception_summary(details),
                        _severity(batch, details),
                        latest_row_id,
                        incident["incident_id"],
                        incident["pipeline_status"],
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "Incident changed during the evidence refresh"
                    )
                changed += 1
                LOGGER.info(
                    "Requeued incident %s after %d appended detail(s)",
                    incident["incident_id"],
                    len(row_ids - prior_ids),
                )

            connection.commit()
            return changed
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
            connection.close()


def run_importer(*, once: bool = False) -> None:
    settings = BatchImporterSettings.from_environment()
    importer = BatchImporter(settings)

    if once:
        inserted = importer.import_new_batches()
        LOGGER.info("Batch import completed; %d incident(s) inserted", inserted)
        return

    LOGGER.info(
        "Starting batch importer with a %d-second poll interval; "
        "late-detail refresh enabled=%s",
        settings.poll_seconds,
        REFRESH_LATE_DETAILS,
    )
    while True:
        try:
            inserted = importer.import_new_batches()
            if inserted:
                LOGGER.info("Imported or requeued %d incident(s)", inserted)
        except Exception:
            LOGGER.exception("Batch import failed")
        time.sleep(settings.poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import replicated alert batches into live_incidents"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one import cycle and exit",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run_importer(once=args.once)


if __name__ == "__main__":
    main()
