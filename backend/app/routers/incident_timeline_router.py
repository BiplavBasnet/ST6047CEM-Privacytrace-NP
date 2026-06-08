from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.incident_timeline_schema import IncidentTimelineResponse
from app.services import incident_timeline_service, permission_service


router = APIRouter(tags=["incident-timeline"])


@router.get("/incidents/{incident_id}/timeline", response_model=IncidentTimelineResponse)
def get_incident_timeline(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TIMELINE_READ))],
    db: Session = Depends(get_db_session),
    event_type: str | None = Query(default=None, max_length=64),
    lifecycle_stage: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=500, ge=1, le=1000),
):
    try:
        return incident_timeline_service.build_timeline(db, incident_id, event_type=event_type, lifecycle_stage=lifecycle_stage, limit=limit)
    except incident_timeline_service.IncidentTimelineError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
