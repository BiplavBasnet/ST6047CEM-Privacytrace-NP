from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.privacy_impact_schema import (
    PrivacyImpactApproveRequest, PrivacyImpactAssessRequest, PrivacyImpactAssessmentRead,
    PrivacyImpactResponse, PrivacyImpactReviewRequest,
)
from app.schemas.privacy_response_schema import AlertReasonRequest, BreachAlertListResponse, BreachAlertRead
from app.services import permission_service, privacy_breach_alert_service, privacy_impact_service

router = APIRouter(tags=["privacy-impact"])


def _impact_error(exc: Exception) -> None:
    if isinstance(exc, privacy_impact_service.PrivacyImpactNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/incidents/{incident_id}/privacy-impact/assess", response_model=PrivacyImpactResponse)
def assess_privacy_impact(
    incident_id: str,
    body: PrivacyImpactAssessRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PRIVACY_IMPACT_ASSESS))],
    db: Session = Depends(get_db_session),
):
    try:
        privacy_impact_service.assess_incident(db, incident_id, body, actor_id=user.id)
        return privacy_impact_service.build_response(db, incident_id)
    except privacy_impact_service.PrivacyImpactError as exc:
        _impact_error(exc)


@router.get("/incidents/{incident_id}/privacy-impact", response_model=PrivacyImpactResponse)
def get_privacy_impact(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PRIVACY_IMPACT_READ))],
    db: Session = Depends(get_db_session),
):
    return privacy_impact_service.build_response(db, incident_id)


@router.post("/privacy-impact/{assessment_id}/review", response_model=PrivacyImpactAssessmentRead)
def review_privacy_impact(
    assessment_id: str,
    body: PrivacyImpactReviewRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PRIVACY_IMPACT_ASSESS))],
    db: Session = Depends(get_db_session),
):
    try:
        return privacy_impact_service.review_assessment(db, assessment_id, body, actor_id=user.id)
    except privacy_impact_service.PrivacyImpactError as exc:
        _impact_error(exc)


@router.post("/privacy-impact/{assessment_id}/approve", response_model=PrivacyImpactAssessmentRead)
def approve_privacy_impact(
    assessment_id: str,
    body: PrivacyImpactApproveRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PRIVACY_IMPACT_APPROVE))],
    db: Session = Depends(get_db_session),
):
    try:
        return privacy_impact_service.approve_assessment(db, assessment_id, actor_id=user.id, reason=body.reason)
    except privacy_impact_service.PrivacyImpactError as exc:
        _impact_error(exc)


@router.get("/incidents/{incident_id}/alerts", response_model=BreachAlertListResponse)
def list_incident_breach_alerts(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_BREACH_ALERT_READ))],
    db: Session = Depends(get_db_session),
):
    alerts = privacy_breach_alert_service.list_alerts(db, incident_id)
    return BreachAlertListResponse(alerts=alerts, total=len(alerts))


def _alert_action(db: Session, alert_id: str, user: User, body: AlertReasonRequest | None, action: str):
    try:
        if action == "acknowledge":
            return privacy_breach_alert_service.acknowledge(db, alert_id, actor_id=user.id)
        return privacy_breach_alert_service.resolve(db, alert_id, actor_id=user.id, reason=body.reason, false_positive=action == "false_positive")
    except privacy_breach_alert_service.BreachAlertNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except privacy_breach_alert_service.BreachAlertError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/acknowledge", response_model=BreachAlertRead)
def acknowledge_breach_alert(alert_id: str, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_BREACH_ALERT_MANAGE))], db: Session = Depends(get_db_session)):
    return _alert_action(db, alert_id, user, None, "acknowledge")


@router.post("/alerts/{alert_id}/resolve", response_model=BreachAlertRead)
def resolve_breach_alert(alert_id: str, body: AlertReasonRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_BREACH_ALERT_MANAGE))], db: Session = Depends(get_db_session)):
    return _alert_action(db, alert_id, user, body, "resolve")


@router.post("/alerts/{alert_id}/mark-false-positive", response_model=BreachAlertRead)
def mark_breach_alert_false_positive(alert_id: str, body: AlertReasonRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_BREACH_ALERT_MANAGE))], db: Session = Depends(get_db_session)):
    return _alert_action(db, alert_id, user, body, "false_positive")
