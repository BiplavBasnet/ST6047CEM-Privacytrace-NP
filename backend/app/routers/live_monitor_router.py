"""Live Privacy Monitor HTTP endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.live_monitor_schema import (
    LiveAlertDismissRequest,
    LiveAlertDismissResponse,
    LiveAlertIncidentRequest,
    LiveAlertIncidentResponse,
    LiveAlertListResponse,
    LiveAlertRead,
    LiveMonitorBatchRequest,
    LiveMonitorBatchResponse,
    LiveMonitorControlResponse,
    LiveMonitorEventRequest,
    LiveMonitorEventResponse,
    LiveMonitorRetestRequest,
    LiveMonitorRetestResponse,
    LiveMonitorStartRequest,
    LiveMonitorStatusResponse,
)
from app.services import live_monitor_service, permission_service
from app.services.live_ingestion_adapter_service import UnsupportedLiveMonitorFormatError
from app.services.live_monitor_service import (
    LiveAlertNotFoundError,
    LiveAlertStateError,
    LiveIncidentNotFoundError,
    LiveMonitorDemoActionNotAllowed,
    LiveMonitorNotRunningError,
)

router = APIRouter(prefix="/live-monitor", tags=["live-monitor"])


@router.get("/status", response_model=LiveMonitorStatusResponse)
def get_live_monitor_status(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_READ))],
    db: Session = Depends(get_db_session),
) -> LiveMonitorStatusResponse:
    return live_monitor_service.get_status(db)


@router.post("/start", response_model=LiveMonitorControlResponse)
def start_live_monitor(
    body: LiveMonitorStartRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_CONTROL))],
    db: Session = Depends(get_db_session),
) -> LiveMonitorControlResponse:
    state = live_monitor_service.start_monitor(
        db,
        body,
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
    )
    return LiveMonitorControlResponse(
        status="started",
        message="Live Privacy Monitor HTTP ingestion is enabled in safe mode." if state.safe_mode else "Live Privacy Monitor HTTP ingestion is enabled.",
        running=state.running,
        safe_mode=state.safe_mode,
    )


@router.post("/stop", response_model=LiveMonitorControlResponse)
def stop_live_monitor(
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_CONTROL))],
    db: Session = Depends(get_db_session),
) -> LiveMonitorControlResponse:
    state = live_monitor_service.stop_monitor(
        db,
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
    )
    return LiveMonitorControlResponse(
        status="stopped",
        message="Live Privacy Monitor ingestion was stopped. The backend remains running.",
        running=state.running,
        safe_mode=state.safe_mode,
    )


@router.post("/events", response_model=LiveMonitorEventResponse)
def ingest_live_event(
    body: LiveMonitorEventRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_INGEST))],
    response: Response,
    db: Session = Depends(get_db_session),
) -> LiveMonitorEventResponse:
    try:
        result = live_monitor_service.process_event(
            db,
            body,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except UnsupportedLiveMonitorFormatError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except LiveMonitorNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if result.status == "rejected":
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    return result


@router.post("/events/batch", response_model=LiveMonitorBatchResponse)
def ingest_live_event_batch(
    body: LiveMonitorBatchRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_INGEST))],
    db: Session = Depends(get_db_session),
) -> LiveMonitorBatchResponse:
    if len(body.events) > 100:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Batch size exceeds 100 events.")
    try:
        return live_monitor_service.process_batch(
            db,
            body.events,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except LiveMonitorNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/test-event", response_model=LiveMonitorEventResponse)
def ingest_test_event(
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_INGEST))],
    db: Session = Depends(get_db_session),
) -> LiveMonitorEventResponse:
    try:
        return live_monitor_service.process_test_event(
            db,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except LiveMonitorDemoActionNotAllowed as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except LiveMonitorNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get("/alerts", response_model=LiveAlertListResponse)
def list_live_alerts(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_READ))],
    db: Session = Depends(get_db_session),
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    severity: str | None = None,
    source_name: str | None = None,
    linked_incident_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> LiveAlertListResponse:
    return live_monitor_service.list_alerts(
        db,
        status=status_filter,
        severity=severity,
        source_name=source_name,
        linked_incident_id=linked_incident_id,
        limit=limit,
    )


@router.get("/alerts/{alert_id}", response_model=LiveAlertRead)
def get_live_alert(
    alert_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_READ))],
    db: Session = Depends(get_db_session),
) -> LiveAlertRead:
    try:
        return live_monitor_service.get_alert_safe(db, alert_id)
    except LiveAlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/create-incident", response_model=LiveAlertIncidentResponse)
def create_or_link_incident_from_alert(
    alert_id: str,
    body: LiveAlertIncidentRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_INCIDENT))],
    db: Session = Depends(get_db_session),
) -> LiveAlertIncidentResponse:
    try:
        return live_monitor_service.create_or_link_incident(
            db,
            alert_id=alert_id,
            mode=body.mode,
            incident_id=body.incident_id,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except LiveAlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except LiveIncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except LiveAlertStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/dismiss", response_model=LiveAlertDismissResponse)
def dismiss_live_alert(
    alert_id: str,
    body: LiveAlertDismissRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_DISMISS))],
    db: Session = Depends(get_db_session),
) -> LiveAlertDismissResponse:
    try:
        return live_monitor_service.dismiss_alert(
            db,
            alert_id=alert_id,
            reason=body.reason,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except LiveAlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except LiveAlertStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/retest-event",
    response_model=LiveMonitorRetestResponse,
)
def record_live_retest_event(
    incident_id: str,
    _body: LiveMonitorRetestRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_LIVE_MONITOR_INGEST)),
    ],
    db: Session = Depends(get_db_session),
) -> LiveMonitorRetestResponse:
    try:
        return live_monitor_service.record_live_retest_event(
            db,
            incident_id=incident_id,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except LiveIncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except LiveMonitorDemoActionNotAllowed as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
