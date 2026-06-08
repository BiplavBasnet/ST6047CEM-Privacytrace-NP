from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.incident_workflow_schema import IncidentWorkflowState
from app.schemas.report_readiness_schema import ReportReadinessResponse
from app.schemas.root_cause_evidence_strength_schema import RootCauseEvidenceStrengthResponse
from app.services import (
    incident_workflow_service,
    permission_service,
    report_readiness_service,
    root_cause_evidence_strength_service,
)

router = APIRouter(prefix="/incidents", tags=["incident-workflow"])


@router.get("/{incident_id}/workflow-state", response_model=IncidentWorkflowState)
def get_incident_workflow_state(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return incident_workflow_service.get_workflow_state(db, incident_id)
    except incident_workflow_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/{incident_id}/root-cause-evidence-strength",
    response_model=RootCauseEvidenceStrengthResponse,
)
def get_incident_root_cause_evidence_strength(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return root_cause_evidence_strength_service.calculate_evidence_strength(db, incident_id)
    except root_cause_evidence_strength_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{incident_id}/report-readiness", response_model=ReportReadinessResponse)
def get_incident_report_readiness(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return report_readiness_service.get_report_readiness(db, incident_id)
    except incident_workflow_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

