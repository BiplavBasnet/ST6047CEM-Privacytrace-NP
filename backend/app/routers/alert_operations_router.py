from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.alert_operations_schema import (
    AlertAssignRequest,
    AlertEscalateRequest,
    AlertEvidenceLinkRead,
    AlertMetricsRead,
    AlertReasonRequest,
    AlertSuppressRequest,
    OperationalAlertListResponse,
    OperationalAlertRead,
    OverdueAlertListResponse,
)
from app.services import alert_operations_service, organisation_access_service as org_access, permission_service


router = APIRouter(tags=["breach-alert-operations"])


def _error(exc: alert_operations_service.AlertOperationError) -> None:
    status = 404 if isinstance(exc, alert_operations_service.AlertNotFoundError) else 409
    raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.get("/breach-alerts", response_model=OperationalAlertListResponse)
def list_breach_alerts(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_READ))],
    db: Session = Depends(get_db_session),
    status: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=32),
    assigned_user_id: int | None = Query(default=None, ge=1),
    include_suppressed: bool = False,
    limit: int = Query(default=200, ge=1, le=500),
):
    alerts = alert_operations_service.list_alerts(db, status=status, severity=severity, assigned_user_id=assigned_user_id, include_suppressed=include_suppressed, limit=limit)
    return OperationalAlertListResponse(alerts=alerts, total=len(alerts))


@router.get("/breach-alerts/metrics", response_model=AlertMetricsRead)
@router.get("/alerts/metrics", response_model=AlertMetricsRead)
def breach_alert_metrics(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_READ))],
    db: Session = Depends(get_db_session),
):
    return alert_operations_service.metrics(db)


@router.get("/breach-alerts/overdue", response_model=OverdueAlertListResponse)
@router.get("/alerts/overdue", response_model=OverdueAlertListResponse)
def list_overdue_breach_alerts(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_READ))],
    db: Session = Depends(get_db_session),
):
    alerts = alert_operations_service.overdue_alerts(db)
    return OverdueAlertListResponse(alerts=alerts, total=len(alerts))


@router.post("/breach-alerts/{alert_id}/assign", response_model=OperationalAlertRead)
@router.post("/alerts/{alert_id}/assign", response_model=OperationalAlertRead)
def assign_breach_alert(
    alert_id: str,
    body: AlertAssignRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        alert_operations_service.assign_alert(db, alert_id, actor_id=user.id, assigned_user_id=body.assigned_user_id, assigned_team=body.assigned_team, reason=body.reason, acknowledgement_deadline=body.acknowledgement_deadline, containment_deadline=body.containment_deadline, escalation_deadline=body.escalation_deadline)
        return alert_operations_service.get_alert_read(db, alert_id)
    except alert_operations_service.AlertOperationError as exc:
        _error(exc)


@router.post("/breach-alerts/{alert_id}/suppress", response_model=OperationalAlertRead)
@router.post("/alerts/{alert_id}/suppress", response_model=OperationalAlertRead)
def suppress_breach_alert(
    alert_id: str,
    body: AlertSuppressRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_MANAGE))],
    db: Session = Depends(get_db_session),
):
    if body.privileged_override:
        try:
            membership = org_access.require_active_membership(db, user)
        except org_access.OrganisationAccessError as extra:
            raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
        if membership.role not in {UserRole.ADMIN, UserRole.PLATFORM_ADMIN}:
            raise HTTPException(
                status_code=403,
                detail="Privileged suppression override requires an administrator.",
            )
    try:
        alert_operations_service.suppress_alert(db, alert_id, actor_id=user.id, reason=body.reason, expires_at=body.expires_at, policy_code=body.policy_code, privileged_override=body.privileged_override)
        return alert_operations_service.get_alert_read(db, alert_id)
    except alert_operations_service.AlertOperationError as exc:
        _error(exc)


@router.post("/breach-alerts/{alert_id}/unsuppress", response_model=OperationalAlertRead)
@router.post("/alerts/{alert_id}/unsuppress", response_model=OperationalAlertRead)
def unsuppress_breach_alert(
    alert_id: str,
    body: AlertReasonRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        alert_operations_service.unsuppress_alert(db, alert_id, actor_id=user.id, reason=body.reason)
        return alert_operations_service.get_alert_read(db, alert_id)
    except alert_operations_service.AlertOperationError as exc:
        _error(exc)


@router.post("/breach-alerts/{alert_id}/escalate", response_model=OperationalAlertRead)
@router.post("/alerts/{alert_id}/escalate", response_model=OperationalAlertRead)
def escalate_breach_alert(
    alert_id: str,
    body: AlertEscalateRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        alert_operations_service.escalate_alert(db, alert_id, actor_id=user.id, level=body.escalation_level, reason=body.reason)
        return alert_operations_service.get_alert_read(db, alert_id)
    except alert_operations_service.AlertOperationError as exc:
        _error(exc)


@router.post("/breach-alerts/{alert_id}/reopen", response_model=OperationalAlertRead)
@router.post("/alerts/{alert_id}/reopen", response_model=OperationalAlertRead)
def reopen_breach_alert(
    alert_id: str,
    body: AlertReasonRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        alert_operations_service.reopen_alert(db, alert_id, actor_id=user.id, reason=body.reason)
        return alert_operations_service.get_alert_read(db, alert_id)
    except alert_operations_service.AlertOperationError as exc:
        _error(exc)


@router.post("/breach-alerts/{alert_id}/evidence/{evidence_id}", response_model=AlertEvidenceLinkRead)
def link_breach_alert_evidence(
    alert_id: str,
    evidence_id: str,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_ALERT_OPERATIONS_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        return alert_operations_service.link_evidence(db, alert_id, evidence_id, actor_id=user.id)
    except alert_operations_service.AlertOperationError as exc:
        _error(exc)

