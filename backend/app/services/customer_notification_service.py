from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.affected_subject import AffectedSubjectReference
from app.models.customer_notification import CustomerNotificationDecision, DeliveryAttempt, NotificationOutbox
from app.models.enums import IncidentStatus
from app.models.incident import Incident
from app.models.privacy_impact import PrivacyImpactAssessment
from app.services import (
    audit_safety_service,
    audit_service,
    privacy_response_provider_service,
    restricted_data_policy_service,
)


class CustomerNotificationError(Exception):
    pass


class CustomerNotificationNotFoundError(CustomerNotificationError):
    pass


class CustomerNotificationStateError(CustomerNotificationError):
    pass


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def _get(db: Session, notification_id: str) -> CustomerNotificationDecision:
    item = db.scalar(select(CustomerNotificationDecision).where(CustomerNotificationDecision.notification_id == notification_id))
    if item is None:
        raise CustomerNotificationNotFoundError(f"Customer notification not found: {notification_id}")
    return item


def _safe_message(incident: Incident, assessment: PrivacyImpactAssessment) -> str:
    from app.services import restricted_data_policy_service
    category_codes, _restricted_present = restricted_data_policy_service.filter_category_codes(
        [str(item) for item in assessment.data_categories or []], channel="customer_notification"
    )
    categories = ", ".join(item.replace("_", " ") for item in category_codes) or "personal information"
    date_text = "the recorded incident period"
    if incident.first_seen and incident.last_seen:
        date_text = f"approximately {incident.first_seen.date().isoformat()} to {incident.last_seen.date().isoformat()}"
    exposure_wording = "was exposed" if assessment.external_access_confirmed else "may have been exposed"
    return (
        f"Incident reference: {incident.incident_id}. We identified that {categories} {exposure_wording} during {date_text}. "
        "The organisation is reviewing the incident and has started protective containment where appropriate. "
        "Please review recent account activity, update credentials if instructed, and contact the approved support channel if you notice unexpected activity. "
        "The investigation is continuing and this notice reflects the information currently verified."
    )


def draft_notification(db: Session, incident_id: str, subject_reference_id: str, *, actor_id: int, locale: str | None = None) -> CustomerNotificationDecision:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise CustomerNotificationNotFoundError(f"Incident not found: {incident_id}")
    if incident.status not in {IncidentStatus.CONFIRMED_INCIDENT, IncidentStatus.FIXED, IncidentStatus.CLOSED}:
        raise CustomerNotificationStateError("Incident must be verified by human review before notification drafting.")
    assessment = db.scalar(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.incident_id == incident_id).order_by(PrivacyImpactAssessment.assessment_version.desc()).limit(1))
    if assessment is None or assessment.status != "approved":
        raise CustomerNotificationStateError("An approved privacy impact assessment is required.")
    from app.services import restricted_data_policy_service
    safe_categories, restricted_only = restricted_data_policy_service.filter_category_codes(
        [str(item) for item in assessment.data_categories or []], channel="customer_notification"
    )
    if restricted_only and not safe_categories:
        raise CustomerNotificationStateError("Customer notification is prohibited for internal-only restricted information.")
    if assessment.privacy_harm_level not in {"high", "critical"}:
        raise CustomerNotificationStateError("Current privacy-harm assessment does not recommend customer notification.")
    subject = db.scalar(select(AffectedSubjectReference).where(AffectedSubjectReference.subject_reference_id == subject_reference_id, AffectedSubjectReference.incident_id == incident_id))
    if subject is None or subject.resolution_status != "resolved" or subject.notification_eligibility != "eligible":
        raise CustomerNotificationStateError("A resolved and eligible affected-subject reference is required.")
    existing = db.scalar(select(CustomerNotificationDecision).where(
        CustomerNotificationDecision.incident_id == incident_id,
        CustomerNotificationDecision.assessment_id == assessment.assessment_id,
        CustomerNotificationDecision.affected_subject_reference_id == subject_reference_id,
    ))
    if existing is not None:
        return existing
    item = CustomerNotificationDecision(
        notification_id=_new_id("NTF"), incident_id=incident_id, assessment_id=assessment.assessment_id,
        affected_subject_reference_id=subject_reference_id, recommendation="recommended",
        reason_codes=["approved_assessment", f"privacy_harm_{assessment.privacy_harm_level}", "resolved_affected_subject"],
        decision_rationale="An approved assessment indicates high potential privacy harm for a resolved affected subject.",
        status="drafted", draft_message=_safe_message(incident, assessment), message_locale=locale or "en", created_by=actor_id,
    )
    db.add(item); db.flush()
    audit_service.log_action(db, action="customer_notification_drafted", actor_id=actor_id, target_type="customer_notification", target_id=item.notification_id,
        details={"incident_id": incident_id, "assessment_id": assessment.assessment_id, "subject_reference_id": subject_reference_id,
                 "recommendation": item.recommendation, "reason_codes": item.reason_codes})
    db.commit(); db.refresh(item)
    return item


def list_notifications(db: Session, incident_id: str) -> list[CustomerNotificationDecision]:
    return list(db.scalars(select(CustomerNotificationDecision).where(CustomerNotificationDecision.incident_id == incident_id).order_by(CustomerNotificationDecision.created_at.desc())).all())


def approve_notification(db: Session, notification_id: str, *, actor_id: int, reason: str) -> CustomerNotificationDecision:
    item = _get(db, notification_id)
    if item.status != "drafted":
        raise CustomerNotificationStateError("Only a drafted notification can be approved.")
    if item.created_by == actor_id:
        raise CustomerNotificationStateError("The draft creator cannot approve the same notification.")
    item.status = "approved"; item.approved_by = actor_id; item.approved_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="customer_notification_approved", actor_id=actor_id, target_type="customer_notification", target_id=notification_id,
        details={"incident_id": item.incident_id, "assessment_id": item.assessment_id, "reason": audit_safety_service.mask_sensitive_text(reason)})
    db.commit(); db.refresh(item)
    return item


def reject_notification(db: Session, notification_id: str, *, actor_id: int, reason: str) -> CustomerNotificationDecision:
    item = _get(db, notification_id)
    if item.status not in {"drafted", "approved"}:
        raise CustomerNotificationStateError("Notification cannot be rejected from its current state.")
    safe_reason = audit_safety_service.mask_sensitive_text(reason)
    item.status = "rejected"; item.rejected_by = actor_id; item.rejected_at = datetime.now(timezone.utc); item.rejection_reason = safe_reason
    audit_service.log_action(db, action="customer_notification_rejected", actor_id=actor_id, target_type="customer_notification", target_id=notification_id,
        details={"incident_id": item.incident_id, "reason": safe_reason})
    db.commit(); db.refresh(item)
    return item


def queue_notification(db: Session, notification_id: str, *, actor_id: int, channel: str) -> NotificationOutbox:
    settings = get_settings()
    if not settings.customer_notification_send_enabled:
        raise CustomerNotificationStateError("External customer notification sending is disabled.")
    item = _get(db, notification_id)
    if item.status not in {"approved", "queued"}:
        raise CustomerNotificationStateError("Notification must be approved before queueing.")
    existing = db.scalar(select(NotificationOutbox).where(NotificationOutbox.notification_id == notification_id, NotificationOutbox.channel == channel))
    if existing is not None:
        return existing
    subject = db.scalar(select(AffectedSubjectReference).where(AffectedSubjectReference.subject_reference_id == item.affected_subject_reference_id))
    if subject is None or subject.notification_eligibility != "eligible":
        raise CustomerNotificationStateError("Notification destination reference is not eligible.")
    key = hashlib.sha256(f"{notification_id}:{channel}".encode("utf-8")).hexdigest()
    outbox = NotificationOutbox(outbox_id=_new_id("OUT"), notification_id=notification_id, channel=channel,
        idempotency_key=key, destination_reference=subject.subject_reference, status="queued", attempt_count=0,
        next_attempt_at=datetime.now(timezone.utc))
    db.add(outbox); item.status = "queued"; db.flush()
    audit_service.log_action(db, action="customer_notification_queued", actor_id=actor_id, target_type="customer_notification", target_id=notification_id,
        details={"incident_id": item.incident_id, "outbox_id": outbox.outbox_id, "channel": channel, "idempotency_key": key})
    db.commit(); db.refresh(outbox)
    return outbox


def delivery_status(db: Session, notification_id: str) -> tuple[CustomerNotificationDecision, list[NotificationOutbox], list[DeliveryAttempt]]:
    item = _get(db, notification_id)
    outbox = list(db.scalars(select(NotificationOutbox).where(NotificationOutbox.notification_id == notification_id).order_by(NotificationOutbox.created_at)).all())
    ids = [record.outbox_id for record in outbox]
    attempts = list(db.scalars(select(DeliveryAttempt).where(DeliveryAttempt.outbox_id.in_(ids)).order_by(DeliveryAttempt.attempted_at)).all()) if ids else []
    return item, outbox, attempts


def process_pending_outbox(db: Session, *, provider: privacy_response_provider_service.NotificationProvider,
                           directory: privacy_response_provider_service.CustomerDirectoryAdapter,
                           now: datetime | None = None) -> int:
    settings = get_settings()
    if not settings.customer_notification_send_enabled:
        return 0
    now = now or datetime.now(timezone.utc)
    rows = list(db.scalars(select(NotificationOutbox).where(
        NotificationOutbox.status.in_(("queued", "retry")), NotificationOutbox.next_attempt_at <= now,
    ).order_by(NotificationOutbox.created_at).with_for_update(skip_locked=True)).all())
    processed = 0
    for outbox in rows:
        notification = _get(db, outbox.notification_id)
        if notification.status not in {"queued", "approved"}:
            continue
        attempt_number = outbox.attempt_count + 1
        try:
            destination = directory.get_delivery_destination(outbox.destination_reference, outbox.channel)
            message, _restricted_present = restricted_data_policy_service.sanitize_text(
                notification.draft_message,
                channel="customer_notification",
            )
            if not message:
                raise privacy_response_provider_service.ProviderDisabledError(
                    "Notification content was blocked by restricted-data policy."
                )
            result = provider.send(destination=destination, message=message, idempotency_key=outbox.idempotency_key)
        except privacy_response_provider_service.ProviderDisabledError:
            result = privacy_response_provider_service.ProviderResult(False, None, "Provider unavailable.", "provider_disabled")
        attempt = DeliveryAttempt(delivery_attempt_id=_new_id("DLA"), outbox_id=outbox.outbox_id,
            attempt_number=attempt_number, status="succeeded" if result.succeeded else "failed",
            error_category=result.error_category, provider_message_reference=result.reference,
            processed_at=now)
        db.add(attempt)
        outbox.attempt_count = attempt_number
        outbox.provider_message_reference = result.reference
        outbox.last_error_category = result.error_category
        if result.succeeded:
            outbox.status = "sent"; outbox.processed_at = now; outbox.next_attempt_at = None; notification.status = "sent"
            action = "customer_notification_delivery_succeeded"
        elif attempt_number >= settings.notification_retry_count:
            outbox.status = "failed"; outbox.processed_at = now; outbox.next_attempt_at = None; notification.status = "failed"
            action = "customer_notification_delivery_failed"
        else:
            outbox.status = "retry"; outbox.next_attempt_at = now + timedelta(seconds=settings.notification_retry_delay_seconds)
            action = "customer_notification_delivery_failed"
        audit_service.log_action(db, action=action, target_type="notification_outbox", target_id=outbox.outbox_id,
            details={"notification_id": notification.notification_id, "channel": outbox.channel, "attempt_number": attempt_number,
                     "status": outbox.status, "error_category": result.error_category})
        processed += 1
    db.commit()
    return processed
