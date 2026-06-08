from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.cicd_evidence_schema import (
    CicdCorrelationResponse,
    CicdEvidenceBatchImport,
    CicdEvidenceImport,
    CicdEvidenceLinkRequest,
    CicdEvidenceListResponse,
    CicdEvidenceRead,
)
from app.services import cicd_evidence_service, permission_service

router = APIRouter(tags=["cicd-evidence"])


def _raise(exc: Exception) -> None:
    if isinstance(
        exc,
        (cicd_evidence_service.IncidentNotFoundError, cicd_evidence_service.CicdEvidenceNotFoundError),
    ):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/cicd-evidence", response_model=CicdEvidenceListResponse)
def list_cicd_evidence(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_READ))
    ],
    incident_id: str | None = None,
    service_name: str | None = None,
    evidence_type: str | None = None,
    limit: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db_session),
):
    try:
        rows = cicd_evidence_service.list_evidence(
            db,
            incident_id=incident_id,
            service_name=service_name,
            evidence_type=evidence_type,
            limit=limit,
        )
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)
    return CicdEvidenceListResponse(
        items=[CicdEvidenceRead.model_validate(row) for row in rows], total=len(rows)
    )


@router.post("/cicd-evidence/import", response_model=CicdEvidenceRead)
def import_cicd_evidence(
    body: CicdEvidenceImport,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_UPLOAD))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return cicd_evidence_service.import_evidence(
            db, body.model_dump(), imported_by=current_user.id
        )
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)


@router.post("/cicd-evidence/import/batch", response_model=CicdEvidenceListResponse)
def import_cicd_evidence_batch(
    body: CicdEvidenceBatchImport,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_UPLOAD))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        rows = cicd_evidence_service.import_evidence_batch(
            db,
            [item.model_dump() for item in body.items],
            imported_by=current_user.id,
        )
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)
    return CicdEvidenceListResponse(
        items=[CicdEvidenceRead.model_validate(row) for row in rows], total=len(rows)
    )


@router.get("/cicd-evidence/{cicd_evidence_id}", response_model=CicdEvidenceRead)
def get_cicd_evidence(
    cicd_evidence_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return cicd_evidence_service.get_evidence(db, cicd_evidence_id)
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)


@router.post("/cicd-evidence/{cicd_evidence_id}/link", response_model=CicdEvidenceRead)
def link_cicd_evidence(
    cicd_evidence_id: str,
    body: CicdEvidenceLinkRequest,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_UPLOAD))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return cicd_evidence_service.link_evidence(
            db,
            cicd_evidence_id,
            incident_id=body.incident_id,
            linked_by=current_user.id,
        )
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)


@router.get(
    "/incidents/{incident_id}/cicd-evidence", response_model=CicdEvidenceListResponse
)
def list_incident_cicd_evidence(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        rows = cicd_evidence_service.list_evidence(db, incident_id=incident_id)
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)
    return CicdEvidenceListResponse(
        items=[CicdEvidenceRead.model_validate(row) for row in rows], total=len(rows)
    )


@router.post(
    "/incidents/{incident_id}/correlate-cicd", response_model=CicdCorrelationResponse
)
def correlate_incident_cicd_evidence(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        candidates = cicd_evidence_service.correlate_evidence(db, incident_id)
    except cicd_evidence_service.CicdEvidenceError as exc:
        _raise(exc)
    return CicdCorrelationResponse(
        incident_id=incident_id, candidates=candidates, total=len(candidates)
    )

