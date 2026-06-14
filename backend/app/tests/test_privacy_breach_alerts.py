"""Detection-to-alert behavior, deduplication, and audit safety."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.models.audit_log import AuditLog
from app.models.breach_alert import BreachAlert
from app.models.containment_action import ContainmentAction
from app.models.enums import UserRole
from app.schemas.privacy_impact_schema import (
    CircumstanceInput,
    PrivacyHarmInput,
    PrivacyImpactAssessRequest,
)
from app.schemas.privacy_response_schema import AlertReasonRequest
from app.services import privacy_breach_alert_service, privacy_impact_service
from app.tests.privacy_response_test_utils import seed_privacy_response_case


def test_detection_creates_suspected_alert_and_deduplicates(db_session):
    case = seed_privacy_response_case(db_session)
    analyst = case["users"][UserRole.SECURITY_ANALYST]
    request = PrivacyImpactAssessRequest()

    assessment, created = privacy_impact_service.assess_incident(
        db_session, case["incident"].incident_id, request, actor_id=analyst.id
    )
    repeated, repeated_created = privacy_impact_service.assess_incident(
        db_session, case["incident"].incident_id, request, actor_id=analyst.id
    )

    alert = db_session.scalar(select(BreachAlert))
    assert created is True
    assert repeated_created is False
    assert repeated.assessment_id == assessment.assessment_id
    assert alert.status == "suspected"
    assert alert.reason_codes == ["customer_data_detected"]
    assert db_session.scalar(select(func.count(BreachAlert.id))) == 1
    assert db_session.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.action == "privacy_impact_factor_added")
    ) >= 2


def test_active_credential_creates_critical_alert_and_containment(db_session):
    case = seed_privacy_response_case(db_session, credential_type="access_token")
    analyst = case["users"][UserRole.SECURITY_ANALYST]
    request = PrivacyImpactAssessRequest(
        ease_of_identification_score=1.0,
        credential_exposure_present=True,
        credential_active=True,
        credential_access_impact="customer_account",
        circumstances=[
            CircumstanceInput(
                code="active_credential_exposure",
                evidence_ids=["DET-PRIVACY-CREDENTIAL"],
                reason="Synthetic evidence indicates the credential remains active.",
            )
        ],
        likely_harms=[
            PrivacyHarmInput(
                harm_category="account_takeover",
                likelihood=4,
                magnitude=3,
                evidence_ids=["DET-PRIVACY-CREDENTIAL"],
                explanation="An active credential could allow account misuse.",
                uncertainty="The accessible scope still requires review.",
                recommended_mitigation="Complete approved credential containment.",
            )
        ],
    )

    assessment, _ = privacy_impact_service.assess_incident(
        db_session, case["incident"].incident_id, request, actor_id=analyst.id
    )
    alert = db_session.scalar(select(BreachAlert))
    containment = db_session.scalar(select(ContainmentAction))

    assert assessment.breach_severity_level == "very_high"
    assert assessment.privacy_harm_level == "critical"
    assert alert.severity == "critical"
    assert alert.status == "suspected"
    assert "active_credential_exposure" in alert.reason_codes
    assert containment.action_type == "revoke_access_token"
    assert containment.status == "recommended"
    assert containment.requires_approval is True


def test_false_positive_requires_reason_and_audit_excludes_raw_value(db_session):
    with pytest.raises(ValidationError):
        AlertReasonRequest(reason="too short")

    case = seed_privacy_response_case(db_session)
    analyst = case["users"][UserRole.SECURITY_ANALYST]
    privacy_impact_service.assess_incident(
        db_session,
        case["incident"].incident_id,
        PrivacyImpactAssessRequest(),
        actor_id=analyst.id,
    )
    alert = db_session.scalar(select(BreachAlert))
    raw_value = "9841234567"
    privacy_breach_alert_service.resolve(
        db_session,
        alert.alert_id,
        actor_id=analyst.id,
        reason=f"Reviewed synthetic match for {raw_value} and classified it as test data.",
        false_positive=True,
    )

    payload = json.dumps(
        {
            "title": alert.title,
            "summary": alert.summary,
            "reason_codes": alert.reason_codes,
            "resolution_reason": alert.resolution_reason,
        }
    )
    audits = json.dumps(
        [row.details for row in db_session.scalars(select(AuditLog)).all()],
        default=str,
    )
    assert raw_value not in payload
    assert raw_value not in audits
    assert alert.status == "false_positive"
