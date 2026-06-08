from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.schemas.incident_schema import (
    AnalyseIncidentItem,
    AnalyseIncidentRequest,
    AnalyseIncidentResponse,
    IncidentDetailRead,
    IncidentRead,
    IncidentTraceResponse,
)
from app.schemas.evidence_graph_schema import EvidenceGraphResponse
from app.schemas.root_cause_schema import RootCauseAnalysisStatus, RootCauseScoreRead
from app.services import causality_engine, evidence_graph_service, organisation_access_service as org_access

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _visible_incident(db: Session, user: User, incident_id: str):
    try:
        return org_access.assert_incident_visible(db, user, incident_id)
    except org_access.OrganisationAccessError as extra:
        raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra


@router.post("/analyse", response_model=AnalyseIncidentResponse)
def analyse_incidents(
    body: AnalyseIncidentRequest,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_WORKFLOW_ANALYSE))
    ],
    db: Session = Depends(get_db_session),
):
    if body.incident_id:
        try:
            _visible_incident(db, current_user, body.incident_id)
            result = causality_engine.analyse_incident(
                db, body.incident_id, force=body.force
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        if result.status == "failed" and result.error:
            raise HTTPException(
                status_code=422,
                detail={"incident_id": body.incident_id, "error": result.error},
            )

        return AnalyseIncidentResponse(
            results=[AnalyseIncidentItem.model_validate(result)],
            total_scored=result.root_cause_count if not result.skipped else 0,
        )

    batch = causality_engine.analyse_all_incidents(db, force=body.force)
    return AnalyseIncidentResponse(
        results=[AnalyseIncidentItem.model_validate(r) for r in batch.results],
        total_scored=batch.total_scored,
    )


@router.get("", response_model=list[IncidentRead])
def list_incidents(
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    membership = org_access.require_active_membership(db, current_user)
    records = org_access.filter_incidents_for_org(
        causality_engine.list_incidents(db), membership.organisation_id
    )
    return [IncidentRead.model_validate(r) for r in records]


@router.get("/{incident_id}", response_model=IncidentDetailRead)
def get_incident(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    record = _visible_incident(db, current_user, incident_id)

    scores = causality_engine.list_root_cause_scores(db, incident_id)
    detail = IncidentDetailRead.model_validate(record)
    detail.root_cause_scores = [RootCauseScoreRead.model_validate(s) for s in scores]
    return detail


@router.get("/{incident_id}/trace", response_model=IncidentTraceResponse)
def get_incident_trace(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    _visible_incident(db, current_user, incident_id)
    try:
        trace = causality_engine.get_incident_trace(db, incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return IncidentTraceResponse.model_validate(trace)


@router.get("/{incident_id}/root-cause-status", response_model=RootCauseAnalysisStatus)
def get_incident_root_cause_status(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    """Versioning/staleness summary for the incident's current root-cause analysis.

    Added without changing `/trace` or `/{incident_id}` response shapes so
    existing clients are unaffected (Phase N).
    """
    _visible_incident(db, current_user, incident_id)
    try:
        status_summary = causality_engine.get_root_cause_status(db, incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RootCauseAnalysisStatus.model_validate(status_summary)


@router.get("/{incident_id}/evidence-graph", response_model=EvidenceGraphResponse)
def get_incident_evidence_graph(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    _visible_incident(db, current_user, incident_id)
    try:
        graph = evidence_graph_service.build_incident_evidence_graph(db, incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return EvidenceGraphResponse.model_validate(graph)
