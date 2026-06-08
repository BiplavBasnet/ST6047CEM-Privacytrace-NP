from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.evidence_provenance_schema import (
    EvidenceProvenanceRead,
    IncidentProvenanceResponse,
    ProvenancePathResponse,
    ProvenanceValidationResponse,
)
from app.services import evidence_provenance_service, integrity_ledger_service, permission_service

router = APIRouter(tags=["evidence-provenance"])


def _error(exc: Exception) -> None:
    if isinstance(exc, evidence_provenance_service.ProvenanceNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/incidents/{incident_id}/provenance",
    response_model=IncidentProvenanceResponse,
)
def get_incident_provenance(
    incident_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    records, relationships = evidence_provenance_service.list_incident_provenance(
        db, incident_id
    )
    statuses = {record.provenance_status for record in records}
    status = (
        "invalid"
        if "invalid" in statuses
        else "partial"
        if "partial" in statuses
        else "complete"
        if records and statuses == {"complete"}
        else "unverified"
    )
    return IncidentProvenanceResponse(
        incident_id=incident_id,
        evidence=records,
        relationships=relationships,
        status=status,
    )


@router.get(
    "/evidence/{evidence_id}/provenance",
    response_model=EvidenceProvenanceRead,
)
def get_evidence_provenance(
    evidence_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return evidence_provenance_service.get_provenance(db, evidence_id)
    except evidence_provenance_service.ProvenanceError as exc:
        _error(exc)


@router.post(
    "/evidence/{evidence_id}/provenance/validate",
    response_model=ProvenanceValidationResponse,
)
def validate_evidence_provenance(
    evidence_id: str,
    user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_VALIDATE)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        record, issues = evidence_provenance_service.validate_provenance(
            db, evidence_id, actor_id=user.id, commit=True
        )
        return ProvenanceValidationResponse(
            evidence_id=evidence_id,
            status=record.provenance_status,
            issues=issues,
            checked_at=datetime.now(timezone.utc),
        )
    except evidence_provenance_service.ProvenanceError as exc:
        _error(exc)


@router.get("/incidents/{incident_id}/provenance/validation")
def validate_incident_provenance(
    incident_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    status, issues = evidence_provenance_service.incident_validation_summary(
        db, incident_id
    )
    return {
        "incident_id": incident_id,
        "status": status,
        "issues": issues,
        "checked_at": datetime.now(timezone.utc),
    }


def _path_response(
    db: Session, *, entity_type: str, entity_id: str
) -> ProvenancePathResponse:
    paths = evidence_provenance_service.build_paths(
        db, entity_type=entity_type, entity_id=entity_id
    )
    return ProvenancePathResponse(
        start_entity_type=entity_type,
        start_entity_id=entity_id,
        paths=paths,
        status="complete" if paths else "unverified",
    )


@router.get(
    "/breach-decisions/{decision_id}/provenance-path",
    response_model=ProvenancePathResponse,
)
def get_decision_provenance_path(
    decision_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    return _path_response(db, entity_type="decision", entity_id=decision_id)


@router.get(
    "/root-causes/{root_cause_id}/provenance-path",
    response_model=ProvenancePathResponse,
)
def get_root_cause_provenance_path(
    root_cause_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    return _path_response(db, entity_type="root_cause", entity_id=root_cause_id)


@router.get("/incidents/{incident_id}/provenance/export")
def export_incident_provenance(
    incident_id: str,
    user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_PROVENANCE_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        integrity_ledger_service.assert_export_allowed(
            db, scope_type="incident", scope_id=incident_id, executed_by=user.id
        )
    except integrity_ledger_service.IntegrityExportBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return evidence_provenance_service.safe_export(db, incident_id)
