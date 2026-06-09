from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.affected_subject import AffectedSubjectReference
from app.models.breach_alert import BreachAlert
from app.models.containment_action import ContainmentAction
from app.services import audit_safety_service, audit_service, privacy_response_provider_service


class ContainmentError(Exception):
    pass


class ContainmentNotFoundError(ContainmentError):
    pass


class ContainmentStateError(ContainmentError):
    pass


def list_actions(db: Session, incident_id: str) -> list[ContainmentAction]:
    return list(db.scalars(select(ContainmentAction).where(ContainmentAction.incident_id == incident_id).order_by(ContainmentAction.created_at)).all())


def _get(db: Session, action_id: str) -> ContainmentAction:
    item = db.scalar(select(ContainmentAction).where(ContainmentAction.containment_action_id == action_id))
    if item is None:
        raise ContainmentNotFoundError(f"Containment action not found: {action_id}")
    return item


def approve(db: Session, action_id: str, *, actor_id: int, reason: str) -> ContainmentAction:
    item = _get(db, action_id)
    if item.status != "recommended":
        raise ContainmentStateError("Only a recommended containment action can be approved.")
    item.status = "approved"
    item.approved_by = actor_id
    item.approved_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="credential_containment_approved", actor_id=actor_id, target_type="containment_action", target_id=action_id,
        details={"incident_id": item.incident_id, "action_type": item.action_type, "reason": audit_safety_service.mask_sensitive_text(reason)})
    db.commit(); db.refresh(item)
    return item


def execute(db: Session, action_id: str, *, actor_id: int, reason: str,
            provider: privacy_response_provider_service.ContainmentProvider | None = None) -> ContainmentAction:
    item = _get(db, action_id)
    if item.status != "approved":
        raise ContainmentStateError("Containment action must be approved before execution.")
    if item.approved_by == actor_id:
        raise ContainmentStateError("The approver cannot execute the same containment action.")
    subject_reference = None
    if item.affected_subject_reference_id:
        subject = db.scalar(select(AffectedSubjectReference).where(AffectedSubjectReference.subject_reference_id == item.affected_subject_reference_id))
        subject_reference = subject.subject_reference if subject else None
    result = (provider or privacy_response_provider_service.DisabledContainmentProvider()).execute(item.action_type, subject_reference, item.credential_type)
    item.executed_by = actor_id
    item.executed_at = datetime.now(timezone.utc)
    item.execution_reference = result.reference
    item.result_summary = audit_safety_service.mask_sensitive_text(result.summary)
    item.failure_reason = result.error_category
    item.status = "executed" if result.succeeded else "manual_action_required"
    if result.succeeded:
        incomplete = int(db.scalar(select(func.count(ContainmentAction.id)).where(
            ContainmentAction.incident_id == item.incident_id,
            ContainmentAction.status != "executed",
        )) or 0)
        if incomplete == 0:
            alerts = list(db.scalars(select(BreachAlert).where(
                BreachAlert.incident_id == item.incident_id,
                BreachAlert.status.in_(("suspected", "verified", "acknowledged", "contained")),
            ).with_for_update()).all())
            for alert in alerts:
                alert.status = "contained"
                alert.contained_at = item.executed_at
    audit_service.log_action(db, action="credential_containment_executed" if result.succeeded else "credential_containment_manual_action_required",
        actor_id=actor_id, target_type="containment_action", target_id=action_id,
        details={"incident_id": item.incident_id, "action_type": item.action_type, "result": item.status, "reason": audit_safety_service.mask_sensitive_text(reason)})
    db.commit(); db.refresh(item)
    return item
