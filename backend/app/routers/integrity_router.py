from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.integrity_schema import (
    IntegrityStatusResponse,
    IntegrityVerificationRunRead,
    IntegrityVerifyRequest,
)
from app.services import integrity_ledger_service, permission_service

router = APIRouter(tags=["integrity"])


def _response(
    *,
    scope_type: str,
    scope_id: str | None,
    records: list,
    latest,
) -> IntegrityStatusResponse:
    status = (
        "verification_failed"
        if latest and not latest.chain_valid
        else "verified"
        if latest and latest.chain_valid
        else "not_yet_verified"
    )
    limitations = []
    if not records:
        limitations.append("No protected records are registered for this scope.")
    if latest is None:
        limitations.append("Integrity has not yet been verified.")
    return IntegrityStatusResponse(
        scope_type=scope_type,
        scope_id=scope_id,
        status=status,
        last_verification=latest,
        records=records,
        limitations=limitations,
    )


@router.post("/integrity/verify", response_model=IntegrityVerificationRunRead)
def verify_integrity(
    body: IntegrityVerifyRequest,
    user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRITY_VERIFY)),
    ],
    db: Session = Depends(get_db_session),
):
    return integrity_ledger_service.verify_ledger(
        db,
        scope_type=body.scope_type,
        scope_id=body.scope_id,
        executed_by=user.id,
    )


@router.post(
    "/incidents/{incident_id}/integrity/verify",
    response_model=IntegrityVerificationRunRead,
)
def verify_incident_integrity(
    incident_id: str,
    user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRITY_VERIFY)),
    ],
    db: Session = Depends(get_db_session),
):
    return integrity_ledger_service.verify_ledger(
        db,
        scope_type="incident",
        scope_id=incident_id,
        executed_by=user.id,
    )


@router.get(
    "/incidents/{incident_id}/integrity",
    response_model=IntegrityStatusResponse,
)
def get_incident_integrity(
    incident_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRITY_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    records, latest = integrity_ledger_service.get_integrity_status(
        db, scope_type="incident", scope_id=incident_id
    )
    return _response(
        scope_type="incident",
        scope_id=incident_id,
        records=records,
        latest=latest,
    )


def _record_response(
    db: Session, *, record_type: str, record_id: str
) -> IntegrityStatusResponse:
    try:
        records, latest = integrity_ledger_service.get_record_integrity(
            db, record_type=record_type, record_id=record_id
        )
    except integrity_ledger_service.IntegrityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _response(
        scope_type=record_type,
        scope_id=record_id,
        records=records,
        latest=latest,
    )


@router.get(
    "/evidence/{evidence_id}/integrity",
    response_model=IntegrityStatusResponse,
)
def get_evidence_integrity(
    evidence_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRITY_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    return _record_response(db, record_type="evidence", record_id=evidence_id)


@router.get(
    "/breach-decisions/{decision_id}/integrity",
    response_model=IntegrityStatusResponse,
)
def get_decision_integrity(
    decision_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRITY_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    return _record_response(
        db, record_type="breach_decision", record_id=decision_id
    )


@router.get(
    "/integrity/verification-runs/{run_id}",
    response_model=IntegrityVerificationRunRead,
)
def get_integrity_verification_run(
    run_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRITY_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return integrity_ledger_service.get_verification_run(db, run_id)
    except integrity_ledger_service.IntegrityNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
