"""Integration coverage for review, subjects, containment, notifications, and RBAC."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.models.containment_action import ContainmentAction
from app.models.enums import IncidentStatus, UserRole
from app.models.privacy_impact import PrivacyImpactFactor
from app.schemas.privacy_impact_schema import PrivacyHarmInput, PrivacyImpactAssessRequest, PrivacyImpactReviewRequest
from app.services import (
    affected_subject_service,
    containment_service,
    customer_notification_service,
    permission_service,
    privacy_impact_service,
    privacy_response_provider_service,
)
from app.tests.privacy_response_test_utils import seed_privacy_response_case


class SuccessfulContainmentProvider:
    def execute(self, action_type, subject_reference, credential_type):
        return privacy_response_provider_service.ProviderResult(
            True,
            "synthetic-execution-reference",
            "Synthetic containment provider completed the approved action.",
        )


def high_harm_request(*, credential: bool = False):
    return PrivacyImpactAssessRequest(
        data_categories=["authentication_data" if credential else "contact_data"],
        credential_exposure_present=credential,
        likely_harms=[
            PrivacyHarmInput(
                harm_category="account_takeover" if credential else "phishing",
                likelihood=3,
                magnitude=4,
                evidence_ids=["DET-PRIVACY-CONTACT"],
                explanation="Reviewed synthetic evidence supports a material potential harm.",
                uncertainty="External use has not been independently observed.",
                recommended_mitigation="Complete review and provide proportionate protective guidance.",
            )
        ],
        limitations=["Synthetic test evidence only."],
    )


def review_and_approve(db, assessment, analyst_id, admin_id):
    factor_ids = list(
        db.scalars(
            select(PrivacyImpactFactor.id).where(
                PrivacyImpactFactor.assessment_id == assessment.assessment_id
            )
        ).all()
    )
    privacy_impact_service.review_assessment(
        db,
        assessment.assessment_id,
        PrivacyImpactReviewRequest(
            decision="accepted",
            reason="Reviewed all score factors and supporting synthetic evidence.",
            accepted_factor_ids=factor_ids,
        ),
        actor_id=analyst_id,
    )
    return privacy_impact_service.approve_assessment(
        db,
        assessment.assessment_id,
        actor_id=admin_id,
        reason="Approved after independent review of factors and limitations.",
    )


def test_subjects_are_hmac_pseudonymous_and_raw_lookup_is_not_audited(db_session):
    case = seed_privacy_response_case(db_session)
    analyst = case["users"][UserRole.SECURITY_ANALYST]
    privacy_impact_service.assess_incident(
        db_session,
        case["incident"].incident_id,
        PrivacyImpactAssessRequest(),
        actor_id=analyst.id,
    )
    raw_lookup = "synthetic-customer-0001"
    first = affected_subject_service.resolve_subject(
        db_session,
        case["incident"].incident_id,
        lookup_token=raw_lookup,
        affected_data_categories=["contact_data"],
        occurrence_count=1,
        credential_types=[],
        actor_id=analyst.id,
    )
    second = affected_subject_service.resolve_subject(
        db_session,
        case["incident"].incident_id,
        lookup_token=raw_lookup,
        affected_data_categories=["financial_data"],
        occurrence_count=1,
        credential_types=[],
        actor_id=analyst.id,
    )

    assert first.subject_reference_id == second.subject_reference_id
    assert first.subject_reference.startswith("SUBJ-H1-")
    assert raw_lookup not in first.subject_reference
    audits = json.dumps(
        [row.details for row in db_session.scalars(select(AuditLog)).all()],
        default=str,
    )
    assert raw_lookup not in audits


def test_notification_requires_approved_assessment_and_separate_approver(db_session):
    case = seed_privacy_response_case(db_session)
    users = case["users"]
    incident = case["incident"]
    assessment, _ = privacy_impact_service.assess_incident(
        db_session,
        incident.incident_id,
        high_harm_request(),
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )
    subject = affected_subject_service.resolve_subject(
        db_session,
        incident.incident_id,
        lookup_token="synthetic-customer-0002",
        affected_data_categories=["contact_data"],
        occurrence_count=1,
        credential_types=[],
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )
    incident.status = IncidentStatus.CONFIRMED_INCIDENT
    db_session.flush()

    with pytest.raises(customer_notification_service.CustomerNotificationStateError):
        customer_notification_service.draft_notification(
            db_session,
            incident.incident_id,
            subject.subject_reference_id,
            actor_id=users[UserRole.SECURITY_ANALYST].id,
        )

    review_and_approve(
        db_session,
        assessment,
        users[UserRole.SECURITY_ANALYST].id,
        users[UserRole.ADMIN].id,
    )
    notification = customer_notification_service.draft_notification(
        db_session,
        incident.incident_id,
        subject.subject_reference_id,
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )

    with pytest.raises(customer_notification_service.CustomerNotificationStateError):
        customer_notification_service.approve_notification(
            db_session,
            notification.notification_id,
            actor_id=users[UserRole.SECURITY_ANALYST].id,
            reason="The same user must not approve their own notification draft.",
        )
    approved = customer_notification_service.approve_notification(
        db_session,
        notification.notification_id,
        actor_id=users[UserRole.ADMIN].id,
        reason="Approved after independent review of the safe customer message.",
    )
    assert approved.status == "approved"
    assert "synthetic-customer-0002" not in approved.draft_message
    with pytest.raises(customer_notification_service.CustomerNotificationStateError):
        customer_notification_service.queue_notification(
            db_session,
            notification.notification_id,
            actor_id=users[UserRole.ADMIN].id,
            channel="email",
        )


def test_containment_requires_approval_and_separate_executor(db_session):
    case = seed_privacy_response_case(db_session, credential_type="api_key")
    users = case["users"]
    privacy_impact_service.assess_incident(
        db_session,
        case["incident"].incident_id,
        high_harm_request(credential=True),
        actor_id=users[UserRole.SECURITY_ANALYST].id,
    )
    action = db_session.scalar(select(ContainmentAction))
    with pytest.raises(containment_service.ContainmentStateError):
        containment_service.execute(
            db_session,
            action.containment_action_id,
            actor_id=users[UserRole.DEVSECOPS_ENGINEER].id,
            reason="Attempted before the required approval was recorded.",
            provider=SuccessfulContainmentProvider(),
        )
    containment_service.approve(
        db_session,
        action.containment_action_id,
        actor_id=users[UserRole.ADMIN].id,
        reason="Approved after reviewing the credential impact and action scope.",
    )
    with pytest.raises(containment_service.ContainmentStateError):
        containment_service.execute(
            db_session,
            action.containment_action_id,
            actor_id=users[UserRole.ADMIN].id,
            reason="The approver cannot execute the same containment action.",
            provider=SuccessfulContainmentProvider(),
        )
    executed = containment_service.execute(
        db_session,
        action.containment_action_id,
        actor_id=users[UserRole.DEVSECOPS_ENGINEER].id,
        reason="Executed through the synthetic non-production provider.",
        provider=SuccessfulContainmentProvider(),
    )
    assert executed.status == "executed"


def test_module_rbac_matches_separation_of_duties():
    assert permission_service.role_has_permission(UserRole.SECURITY_ANALYST, "privacy_impact:assess")
    assert not permission_service.role_has_permission(UserRole.SECURITY_ANALYST, "privacy_impact:approve")
    assert permission_service.role_has_permission(UserRole.ADMIN, "customer_notification:approve")
    assert permission_service.role_has_permission(UserRole.DEVSECOPS_ENGINEER, "containment:execute")
    assert permission_service.role_has_permission(UserRole.AUDITOR, "customer_notification:read")
    assert not permission_service.role_has_permission(UserRole.AUDITOR, "customer_notification:approve")
    assert not permission_service.role_has_permission(UserRole.DEVELOPER, "privacy_impact:read")
