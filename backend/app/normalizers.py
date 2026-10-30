from __future__ import annotations

import hashlib
import json
from typing import Any, Optional


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_object(value: Any) -> Optional[dict[str, Any]]:
    """Return a stored JSON object, or None for missing or invalid data."""

    if isinstance(value, dict):
        return value
    if not isinstance(value, (str, bytes, bytearray)) or not value:
        return None
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def normalize_proposer(root_cause: Any, proposed_fix: Any) -> dict[str, Any]:
    """Expose the stored Proposer dossier without altering its contents."""

    raw_root = "" if root_cause is None else str(root_cause)
    raw_fix = "" if proposed_fix is None else str(proposed_fix)
    parsed = _json_object(root_cause)

    if parsed is not None and "proposed_root_cause" in parsed:
        agent_fix = str(parsed.get("proposed_actionable_fix") or "").strip()
        fallback_fix = raw_fix.strip()
        if fallback_fix.startswith("## Proposed Actionable Fix"):
            fallback_fix = fallback_fix.removeprefix(
                "## Proposed Actionable Fix"
            ).strip()
        if fallback_fix == "See ai_proposed_root_cause for fix details.":
            fallback_fix = ""
        return {
            "root_cause": str(parsed.get("proposed_root_cause") or "").strip(),
            "actionable_fix": agent_fix or fallback_fix,
            "historical_confidence_score": parsed.get("historical_confidence_score"),
            "is_historical_match": parsed.get("is_historical_match"),
            "raw": raw_root,
        }

    return {
        "root_cause": raw_root,
        "actionable_fix": raw_fix,
        "historical_confidence_score": None,
        "is_historical_match": None,
        "raw": raw_root,
    }


def normalize_incident(row: dict[str, Any]) -> dict[str, Any]:
    """Keep the existing incident API and expose structured analysis when present.

    This parses stored JSON only. The repository must check current source
    evidence before it marks an AI answer eligible for engineer review.
    """

    proposer = normalize_proposer(
        row.get("ai_proposed_root_cause"), row.get("ai_proposed_fix")
    )
    return {
        "incident_id": row["incident_id"],
        "source_system": row.get("source_system"),
        "component_id": row.get("component_id"),
        "exception_type": row.get("exception_type"),
        "error_message": row.get("error_message"),
        "pipeline_status": row.get("pipeline_status"),
        "proposer": proposer,
        "verifier_markdown": row.get("ai_verifier_result") or "",
        "verifier_findings": _json_object(row.get("ai_verifier_findings")),
        "final_assessment": _json_object(row.get("ai_final_assessment")),
    }
