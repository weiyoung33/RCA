from __future__ import annotations

from typing import Annotated, Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from .config import settings
from .repository_old import (
    approve_remediation_request,
    create_remediation_request,
    list_remediation_actions,
    list_remediation_requests,
    reject_remediation_request,
    resolve_manual_remediation,
)
from .schemas import (
    RemediationDecisionRequest,
    RemediationManualResolutionRequest,
    RemediationRequestCreate,
)


router = APIRouter(tags=["remediations"])


def current_engineer() -> str:
    """
    Return the prototype backend identity used for
    remediation auditing.
    """

    if settings.dev_user_role not in {
        "engineer",
        "admin",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Engineer access is required",
        )

    return settings.dev_user_name


Engineer = Annotated[
    str,
    Depends(current_engineer),
]


@router.get("/api/remediations/actions")
def remediation_actions(
    component_id: Optional[str] = Query(
        default=None,
        max_length=255,
    ),
) -> dict[str, Any]:
    """
    Return database-registered actions, optionally
    filtered by component.
    """

    return {
        "items": list_remediation_actions(
            component_id,
        ),
    }


@router.get("/api/remediations")
def remediations(
    incident_id: Optional[int] = Query(
        default=None,
        ge=1,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
) -> dict[str, Any]:
    """
    Return remediation requests, optionally filtered
    by incident.
    """

    return {
        "items": list_remediation_requests(
            incident_id,
            limit,
        ),
    }


@router.post(
    "/api/incidents/{incident_id}/remediations",
    status_code=status.HTTP_201_CREATED,
)
def request_remediation(
    incident_id: int,
    request: RemediationRequestCreate,
    engineer: Engineer,
) -> dict[str, Any]:
    """
    Create a pending request from one ACTIVE catalog
    action.
    """

    try:
        result = create_remediation_request(
            incident_id=incident_id,
            action_id=request.action_id,
            request_reason=request.request_reason,
            requested_by=engineer,
            idempotency_key=request.idempotency_key,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return result


@router.post(
    "/api/remediations/{remediation_id}/approve",
)
def approve_remediation(
    remediation_id: int,
    decision: RemediationDecisionRequest,
    engineer: Engineer,
) -> dict[str, Any]:
    """
    Approve a pending request without executing it in
    the API process.
    """

    try:
        result = approve_remediation_request(
            remediation_id=remediation_id,
            approved_by=engineer,
            comment=decision.comment,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation request not found",
        )

    return result


@router.post(
    "/api/remediations/{remediation_id}/reject",
)
def reject_remediation(
    remediation_id: int,
    decision: RemediationDecisionRequest,
    engineer: Engineer,
) -> dict[str, Any]:
    """
    Reject a pending request and record the engineer
    decision.
    """

    try:
        result = reject_remediation_request(
            remediation_id=remediation_id,
            rejected_by=engineer,
            comment=decision.comment,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation request not found",
        )

    return result


@router.post(
    "/api/remediations/{remediation_id}/resolve-manual",
)
def resolve_manual_remediation_request(
    remediation_id: int,
    resolution: RemediationManualResolutionRequest,
    engineer: Engineer,
) -> dict[str, Any]:
    """
    Record an engineer's outcome for a MANUAL_REVIEW
    request.
    """

    try:
        result = resolve_manual_remediation(
            remediation_id=remediation_id,
            outcome=resolution.outcome,
            resolved_by=engineer,
            comment=resolution.comment,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation request not found",
        )

    return result