from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.privacy_response_schema import (
    ActionApprovalRequest, AffectedSubjectListResponse, AffectedSubjectRead, AffectedSubjectResolveRequest,
    ContainmentActionListResponse, ContainmentActionRead, CustomerNotificationDecisionRead,
    CustomerNotificationDraftRequest, CustomerNotificationListResponse, NotificationDeliveryStatusResponse,
    NotificationOutboxRead, NotificationQueueRequest,
)
from app.services import affected_subject_service, containment_service, customer_notification_service, permission_service

router = APIRouter(tags=["privacy-response"])


def _error(exc: Exception) -> None:
    if isinstance(exc, (containment_service.ContainmentNotFoundError, customer_notification_service.CustomerNotificationNotFoundError)):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/incidents/{incident_id}/affected-subjects", response_model=AffectedSubjectListResponse)
def list_affected_subjects(incident_id: str, _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AFFECTED_SUBJECT_READ))], db: Session = Depends(get_db_session)):
    items = affected_subject_service.list_subjects(db, incident_id)
    return AffectedSubjectListResponse(subjects=items, total=len(items))


@router.post("/incidents/{incident_id}/affected-subjects/resolve", response_model=AffectedSubjectRead)
def resolve_affected_subject(incident_id: str, body: AffectedSubjectResolveRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AFFECTED_SUBJECT_RESOLVE))], db: Session = Depends(get_db_session)):
    try:
        return affected_subject_service.resolve_subject(db, incident_id, lookup_token=body.directory_lookup_token.get_secret_value(),
            affected_data_categories=body.affected_data_categories, occurrence_count=body.occurrence_count,
            credential_types=body.credential_types, subject_type=body.subject_type, actor_id=user.id)
    except affected_subject_service.AffectedSubjectError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/incidents/{incident_id}/containment-actions", response_model=ContainmentActionListResponse)
def list_containment_actions(incident_id: str, _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CONTAINMENT_READ))], db: Session = Depends(get_db_session)):
    items = containment_service.list_actions(db, incident_id)
    return ContainmentActionListResponse(actions=items, total=len(items))


@router.post("/containment-actions/{action_id}/approve", response_model=ContainmentActionRead)
def approve_containment_action(action_id: str, body: ActionApprovalRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CONTAINMENT_APPROVE))], db: Session = Depends(get_db_session)):
    try:
        return containment_service.approve(db, action_id, actor_id=user.id, reason=body.reason)
    except containment_service.ContainmentError as exc:
        _error(exc)


@router.post("/containment-actions/{action_id}/execute", response_model=ContainmentActionRead)
def execute_containment_action(action_id: str, body: ActionApprovalRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CONTAINMENT_EXECUTE))], db: Session = Depends(get_db_session)):
    try:
        return containment_service.execute(db, action_id, actor_id=user.id, reason=body.reason)
    except containment_service.ContainmentError as exc:
        _error(exc)


@router.get("/incidents/{incident_id}/customer-notifications", response_model=CustomerNotificationListResponse)
def list_customer_notifications(incident_id: str, _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CUSTOMER_NOTIFICATION_READ))], db: Session = Depends(get_db_session)):
    items = customer_notification_service.list_notifications(db, incident_id)
    return CustomerNotificationListResponse(notifications=items, total=len(items), sending_enabled=get_settings().customer_notification_send_enabled)


@router.post("/incidents/{incident_id}/customer-notifications/draft", response_model=CustomerNotificationDecisionRead)
def draft_customer_notification(incident_id: str, body: CustomerNotificationDraftRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CUSTOMER_NOTIFICATION_DRAFT))], db: Session = Depends(get_db_session)):
    try:
        return customer_notification_service.draft_notification(db, incident_id, body.affected_subject_reference_id, actor_id=user.id, locale=body.message_locale)
    except customer_notification_service.CustomerNotificationError as exc:
        _error(exc)


@router.post("/customer-notifications/{notification_id}/approve", response_model=CustomerNotificationDecisionRead)
def approve_customer_notification(notification_id: str, body: ActionApprovalRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CUSTOMER_NOTIFICATION_APPROVE))], db: Session = Depends(get_db_session)):
    try:
        return customer_notification_service.approve_notification(db, notification_id, actor_id=user.id, reason=body.reason)
    except customer_notification_service.CustomerNotificationError as exc:
        _error(exc)


@router.post("/customer-notifications/{notification_id}/reject", response_model=CustomerNotificationDecisionRead)
def reject_customer_notification(notification_id: str, body: ActionApprovalRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CUSTOMER_NOTIFICATION_APPROVE))], db: Session = Depends(get_db_session)):
    try:
        return customer_notification_service.reject_notification(db, notification_id, actor_id=user.id, reason=body.reason)
    except customer_notification_service.CustomerNotificationError as exc:
        _error(exc)


@router.post("/customer-notifications/{notification_id}/queue", response_model=NotificationOutboxRead)
def queue_customer_notification(notification_id: str, body: NotificationQueueRequest, user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CUSTOMER_NOTIFICATION_QUEUE))], db: Session = Depends(get_db_session)):
    try:
        return customer_notification_service.queue_notification(db, notification_id, actor_id=user.id, channel=body.channel)
    except customer_notification_service.CustomerNotificationError as exc:
        _error(exc)


@router.get("/customer-notifications/{notification_id}/delivery-status", response_model=NotificationDeliveryStatusResponse)
def get_customer_notification_delivery_status(notification_id: str, _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_CUSTOMER_NOTIFICATION_READ))], db: Session = Depends(get_db_session)):
    try:
        notification, outbox, attempts = customer_notification_service.delivery_status(db, notification_id)
        return NotificationDeliveryStatusResponse(notification=notification, outbox=outbox, attempts=attempts, sending_enabled=get_settings().customer_notification_send_enabled)
    except customer_notification_service.CustomerNotificationError as exc:
        _error(exc)
