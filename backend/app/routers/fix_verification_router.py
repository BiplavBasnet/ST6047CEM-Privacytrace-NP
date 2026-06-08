from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.schemas.verification_schema import (
    FixVerificationListResponse,
    FixVerificationRead,
    VerifyFixRequest,
    VerifyFixResponse,
)
from app.services import fix_verification_service
from app.services.fix_verification_gate_service import FixVerificationNotAllowedError

router = APIRouter(prefix="/incidents", tags=["fix-verification"])


@router.post("/{incident_id}/verify-fix", response_model=VerifyFixResponse)
def verify_incident_fix(
    incident_id: str,
    body: VerifyFixRequest,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_FIX_VERIFY))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        result = fix_verification_service.verify_fix(
            db,
            incident_id,
            retest_evidence_ids=body.retest_evidence_ids,
            controlled_retest_id=body.controlled_retest_id,
            requested_by=current_user.id,
        )
    except fix_verification_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FixVerificationNotAllowedError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except fix_verification_service.RetestEvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except fix_verification_service.RetestEvidenceNotLinkedError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    v = result.verification
    return VerifyFixResponse(
        verification_id=v.id,
        incident_id=v.incident_id,
        verification_status=v.verification_status.value,
        checks_run=list(v.checks_run or []),
        passed_checks=list(v.passed_checks or []),
        failed_checks=list(v.failed_checks or []),
        evidence_used=list(v.evidence_used or []),
        human_review_required=result.human_review_required,
        safe_summary=result.safe_summary,
        incident_status=result.incident_status.value,
        verification_outcome_id=result.verification_outcome_id,
        eligible_for_learning=result.eligible_for_learning,
    )


@router.get("/{incident_id}/fix-verifications", response_model=FixVerificationListResponse)
def list_incident_fix_verifications(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_FIX_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        rows = fix_verification_service.list_fix_verifications(db, incident_id)
    except fix_verification_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    items = [FixVerificationRead.model_validate(r) for r in rows]
    return FixVerificationListResponse(
        incident_id=incident_id,
        verifications=items,
        total=len(items),
    )
