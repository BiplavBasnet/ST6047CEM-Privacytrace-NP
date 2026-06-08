from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.preventive_control_schema import (
    PreventiveControlGenerateRequest,
    PreventiveControlImplementationRequest,
    PreventiveControlListResponse,
    PreventiveControlRead,
    PreventiveControlReasonRequest,
    PreventiveControlReviewRequest,
    PreventiveControlVerifyRequest,
)
from app.services import permission_service, preventive_control_service


router = APIRouter(tags=["preventive-controls"])


def _error(exc: preventive_control_service.PreventiveControlError) -> None:
    status = 404 if isinstance(exc, preventive_control_service.PreventiveControlNotFoundError) else 409
    raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.get("/incidents/{incident_id}/preventive-controls", response_model=PreventiveControlListResponse)
def list_preventive_controls(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_READ))],
    db: Session = Depends(get_db_session),
):
    items = preventive_control_service.list_controls(db, incident_id)
    return PreventiveControlListResponse(incident_id=incident_id, controls=items, total=len(items))


@router.post("/incidents/{incident_id}/preventive-controls/generate", response_model=PreventiveControlListResponse)
def generate_preventive_controls(
    incident_id: str,
    body: PreventiveControlGenerateRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_GENERATE))],
    db: Session = Depends(get_db_session),
):
    try:
        items = preventive_control_service.generate_controls(db, incident_id, root_cause_id=body.root_cause_id, actor_id=user.id, control_types=body.control_types, affected_component=body.affected_component, use_ai=body.use_ai)
        return PreventiveControlListResponse(incident_id=incident_id, controls=items, total=len(items))
    except preventive_control_service.PreventiveControlError as exc:
        _error(exc)


@router.post("/preventive-controls/{control_id}/review", response_model=PreventiveControlRead)
def review_preventive_control(
    control_id: str,
    body: PreventiveControlReviewRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_REVIEW))],
    db: Session = Depends(get_db_session),
):
    try:
        return preventive_control_service.review_control(db, control_id, actor_id=user.id, decision=body.decision, reason=body.reason)
    except preventive_control_service.PreventiveControlError as exc:
        _error(exc)


@router.post("/preventive-controls/{control_id}/approve", response_model=PreventiveControlRead)
def approve_preventive_control(
    control_id: str,
    body: PreventiveControlReasonRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_APPROVE))],
    db: Session = Depends(get_db_session),
):
    try:
        return preventive_control_service.approve_control(db, control_id, actor_id=user.id, reason=body.reason)
    except preventive_control_service.PreventiveControlError as exc:
        _error(exc)


@router.post("/preventive-controls/{control_id}/implement", response_model=PreventiveControlRead)
@router.post("/preventive-controls/{control_id}/mark-implemented", response_model=PreventiveControlRead)
def implement_preventive_control(
    control_id: str,
    body: PreventiveControlImplementationRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_IMPLEMENT))],
    db: Session = Depends(get_db_session),
):
    try:
        return preventive_control_service.implement_control(db, control_id, actor_id=user.id, implementation_reference=body.implementation_reference, remediation_action_id=body.remediation_action_id, reason=body.reason)
    except preventive_control_service.PreventiveControlError as exc:
        _error(exc)


@router.post("/preventive-controls/{control_id}/verify", response_model=PreventiveControlRead)
def verify_preventive_control(
    control_id: str,
    body: PreventiveControlVerifyRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_VERIFY))],
    db: Session = Depends(get_db_session),
):
    try:
        return preventive_control_service.verify_control(db, control_id, actor_id=user.id, verification_method=body.verification_method, verification_result=body.verification_result, passed=body.passed, retest_evidence_ids=body.retest_evidence_ids, reason=body.reason)
    except preventive_control_service.PreventiveControlError as exc:
        _error(exc)


@router.post("/preventive-controls/{control_id}/retire", response_model=PreventiveControlRead)
def retire_preventive_control(
    control_id: str,
    body: PreventiveControlReasonRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_PREVENTIVE_CONTROL_APPROVE))],
    db: Session = Depends(get_db_session),
):
    try:
        return preventive_control_service.retire_control(db, control_id, actor_id=user.id, reason=body.reason)
    except preventive_control_service.PreventiveControlError as exc:
        _error(exc)

