"""Transactional outbox retry and idempotency coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.config import get_settings
from app.models.customer_notification import DeliveryAttempt, NotificationOutbox
from app.models.enums import IncidentStatus, UserRole
from app.schemas.privacy_impact_schema import PrivacyHarmInput, PrivacyImpactAssessRequest, PrivacyImpactReviewRequest
from app.models.privacy_impact import PrivacyImpactFactor
from app.services import (
    affected_subject_service,
    customer_notification_service,
    privacy_impact_service,
    privacy_response_provider_service,
)
from app.tests.privacy_response_test_utils import seed_privacy_response_case


class FakeNotificationProvider:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.idempotency_keys = []

    def send(self, *, destination, message, idempotency_key):
        self.idempotency_keys.append(idempotency_key)
        succeeded = self.outcomes.pop(0)
        return privacy_response_provider_service.ProviderResult(
            succeeded,
            "fake-provider-reference" if succeeded else None,
            "Synthetic provider result.",
            None if succeeded else "temporary_failure",
        )


def test_webhook_signatures_are_stable_and_keyed():
    payload = b'{"notification_id":"NTF-SYNTHETIC"}'
    first = privacy_response_provider_service.sign_webhook_payload(payload, "synthetic-key-one")
    repeated = privacy_response_provider_service.sign_webhook_payload(payload, "synthetic-key-one")
    different = privacy_response_provider_service.sign_webhook_payload(payload, "synthetic-key-two")
    assert first == repeated
    assert first != different
    assert first.startswith("sha256=")

@pytest.fixture
def delivery_enabled(monkeypatch):
    monkeypatch.setenv("CUSTOMER_NOTIFICATION_SEND_ENABLED", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def approved_notification(db):
    case = seed_privacy_response_case(db)
    users = case["users"]
    incident = case["incident"]
    assessment, _ = privacy_impact_service.assess_incident(
        db,
        incident.incident_id,
        PrivacyImpactAssessRequest(
            data_categories=["contact_data"],
            likely_harms=[
                PrivacyHarmInput(
                    harm_category="phishing",
                    likelihood=3,
                    magnitude=4,
                    evidence_ids=["DET-PRIVACY-CONTACT"],
                    explanation="Synthetic evidence supports material phishing risk.",
                    uncertainty="External use has not been observed.",
                    recommended_mitigation="Provide reviewed protective guidance.",
                )
            ],
        ),
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )
    directory = privacy_response_provider_service.SyntheticCustomerDirectoryAdapter()
    subject = affected_subject_service.resolve_subject(
        db,
        incident.incident_id,
        lookup_token="synthetic-outbox-customer",
        affected_data_categories=["contact_data"],
        occurrence_count=1,
        credential_types=[],
        actor_id=users[UserRole.SECURITY_ANALYST].id,
        adapter=directory,
    )
    incident.status = IncidentStatus.CONFIRMED_INCIDENT
    db.flush()
    factor_ids = list(db.scalars(select(PrivacyImpactFactor.id).where(PrivacyImpactFactor.assessment_id == assessment.assessment_id)).all())
    privacy_impact_service.review_assessment(
        db,
        assessment.assessment_id,
        PrivacyImpactReviewRequest(
            decision="accepted",
            reason="Reviewed every score factor and synthetic evidence reference.",
            accepted_factor_ids=factor_ids,
        ),
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )
    privacy_impact_service.approve_assessment(
        db,
        assessment.assessment_id,
        actor_id=users[UserRole.ADMIN].id,
        reason="Approved after independent review of the assessment.",
    )
    notification = customer_notification_service.draft_notification(
        db,
        incident.incident_id,
        subject.subject_reference_id,
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )
    customer_notification_service.approve_notification(
        db,
        notification.notification_id,
        actor_id=users[UserRole.ADMIN].id,
        reason="Approved the safe synthetic customer notification.",
    )
    return case, directory, notification


def test_disabled_delivery_does_not_process(db_session):
    provider = FakeNotificationProvider([True])
    assert customer_notification_service.process_pending_outbox(
        db_session,
        provider=provider,
        directory=privacy_response_provider_service.DisabledCustomerDirectoryAdapter(),
    ) == 0
    assert provider.idempotency_keys == []


def test_queue_and_delivery_are_idempotent(db_session, delivery_enabled):
    case, directory, notification = approved_notification(db_session)
    admin_id = case["users"][UserRole.ADMIN].id
    first = customer_notification_service.queue_notification(
        db_session, notification.notification_id, actor_id=admin_id, channel="email"
    )
    repeated = customer_notification_service.queue_notification(
        db_session, notification.notification_id, actor_id=admin_id, channel="email"
    )
    assert repeated.outbox_id == first.outbox_id
    assert db_session.scalar(select(func.count(NotificationOutbox.id))) == 1

    provider = FakeNotificationProvider([True])
    assert customer_notification_service.process_pending_outbox(
        db_session, provider=provider, directory=directory
    ) == 1
    assert customer_notification_service.process_pending_outbox(
        db_session, provider=provider, directory=directory
    ) == 0
    assert db_session.scalar(select(func.count(DeliveryAttempt.id))) == 1
    assert len(set(provider.idempotency_keys)) == 1


def test_failed_delivery_retries_with_same_idempotency_key(db_session, delivery_enabled):
    case, directory, notification = approved_notification(db_session)
    outbox = customer_notification_service.queue_notification(
        db_session,
        notification.notification_id,
        actor_id=case["users"][UserRole.ADMIN].id,
        channel="email",
    )
    provider = FakeNotificationProvider([False, True])
    now = datetime.now(timezone.utc) + timedelta(seconds=1)

    assert customer_notification_service.process_pending_outbox(
        db_session, provider=provider, directory=directory, now=now
    ) == 1
    db_session.refresh(outbox)
    assert outbox.status == "retry"
    assert customer_notification_service.process_pending_outbox(
        db_session,
        provider=provider,
        directory=directory,
        now=now + timedelta(seconds=get_settings().notification_retry_delay_seconds + 1),
    ) == 1
    db_session.refresh(outbox)
    assert outbox.status == "sent"
    assert provider.idempotency_keys == [outbox.idempotency_key, outbox.idempotency_key]
    assert db_session.scalar(select(func.count(DeliveryAttempt.id))) == 2
