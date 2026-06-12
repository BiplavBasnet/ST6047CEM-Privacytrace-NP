from datetime import datetime, timedelta, timezone

import pytest

from app.models.breach_alert import BreachAlert
from app.services.alert_operations_service import calculate_metrics, overdue_reasons, recommended_escalation_level


def _alert(**overrides) -> BreachAlert:
    now = datetime(2026, 7, 17, 8, 0, tzinfo=timezone.utc)
    values = {
        "alert_id": "BAL-1",
        "incident_id": "INC-1",
        "assessment_id": "PIA-1",
        "alert_type": "active_credential_exposure",
        "severity": "critical",
        "status": "suspected",
        "title": "Possible credential exposure",
        "summary": "A masked credential category requires review.",
        "reason_codes": ["active_credential"],
        "deduplication_key": "dedupe-1",
        "credential_exposure_present": True,
        "triggered_at": now,
        "acknowledgement_deadline": now + timedelta(minutes=30),
        "containment_deadline": now + timedelta(hours=2),
        "duplicate_count": 3,
        "occurrence_count": 4,
        "escalation_level": "none",
        "reopened_count": 0,
    }
    values.update(overrides)
    return BreachAlert(**values)


def test_overdue_critical_credential_recommends_security_lead():
    alert = _alert()
    reasons = overdue_reasons(alert, now=alert.triggered_at + timedelta(hours=3))
    assert reasons == ["acknowledgement_deadline_exceeded", "containment_deadline_exceeded"]
    assert recommended_escalation_level(alert, reasons) == "security_lead"


def test_metrics_count_occurrences_suppression_and_duplicate_prevention():
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    active = _alert(
        acknowledged_at=datetime(2026, 7, 17, 8, 10, tzinfo=timezone.utc),
        suppression_started_at=datetime(2026, 7, 17, 8, 20, tzinfo=timezone.utc),
        suppression_expires_at=datetime(2026, 7, 18, 8, 20, tzinfo=timezone.utc),
        reopened_count=2,
    )
    closed = _alert(
        alert_id="BAL-2",
        deduplication_key="dedupe-2",
        severity="high",
        status="false_positive",
        duplicate_count=1,
        credential_exposure_present=False,
    )
    metrics = calculate_metrics([active, closed], now=now)
    assert metrics.total_alerts == 2
    assert metrics.active_alerts == 1
    assert metrics.suppressed_alerts == 1
    assert metrics.duplicate_alerts_prevented == 4
    assert metrics.false_positive_alerts == 1
    assert metrics.reopened_alerts == 2
    assert metrics.median_acknowledgement_seconds == 600



from sqlalchemy import select

from app.models.containment_action import ContainmentAction
from app.models.enums import UserRole
from app.schemas.privacy_impact_schema import PrivacyImpactAssessRequest
from app.services import alert_operations_service, privacy_breach_alert_service, privacy_impact_service
from app.services.privacy_breach_alert_service import _dedupe_key, _dedupe_window
from app.tests.privacy_response_test_utils import seed_privacy_response_case


def test_dedupe_window_produces_stable_key_only_within_window():
    start = datetime(2026, 7, 17, 8, 15, tzinfo=timezone.utc)
    first_window = _dedupe_window(start, 3600)
    same_window = _dedupe_window(start + timedelta(minutes=30), 3600)
    next_window = _dedupe_window(start + timedelta(hours=1), 3600)
    assert _dedupe_key("signature", first_window) == _dedupe_key("signature", same_window)
    assert _dedupe_key("signature", first_window) != _dedupe_key("signature", next_window)


@pytest.mark.critical_db
def test_assignment_preserves_deadlines_and_reopen_resets_state(db_session):
    case = seed_privacy_response_case(db_session)
    analyst = case["users"][UserRole.SECURITY_ANALYST]
    privacy_impact_service.assess_incident(
        db_session,
        case["incident"].incident_id,
        PrivacyImpactAssessRequest(),
        actor_id=analyst.id,
    )
    alert = db_session.scalar(select(BreachAlert))
    original_deadlines = (
        alert.acknowledgement_deadline,
        alert.containment_deadline,
        alert.escalation_deadline,
    )

    alert_operations_service.assign_alert(
        db_session,
        alert.alert_id,
        actor_id=analyst.id,
        assigned_user_id=None,
        assigned_team="privacy-response",
        reason="Assigning the privacy response team.",
    )
    assert (
        alert.acknowledgement_deadline,
        alert.containment_deadline,
        alert.escalation_deadline,
    ) == original_deadlines

    privacy_breach_alert_service.resolve(
        db_session,
        alert.alert_id,
        actor_id=analyst.id,
        reason="Reviewed and resolved for reopen regression coverage.",
    )
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.suppression_started_at = datetime.now(timezone.utc)
    alert.suppression_reason = "Temporary test suppression."
    alert.escalation_level = "security_lead"
    db_session.commit()

    reopened = alert_operations_service.reopen_alert(
        db_session,
        alert.alert_id,
        actor_id=analyst.id,
        reason="New evidence requires renewed operational review.",
    )
    assert reopened.status == "suspected"
    assert reopened.acknowledged_at is None
    assert reopened.suppression_started_at is None
    assert reopened.escalation_level == "none"
    assert reopened.acknowledgement_deadline > datetime.now(timezone.utc)


def test_containment_metrics_use_executed_action_timestamp():
    triggered = datetime(2026, 7, 17, 8, 0, tzinfo=timezone.utc)
    alert = _alert(triggered_at=triggered, contained_at=None)
    action = ContainmentAction(
        containment_action_id="CTA-METRIC",
        incident_id=alert.incident_id,
        action_type="revoke_access_token",
        status="executed",
        reason="Synthetic metric action.",
        requires_approval=True,
        executed_at=triggered + timedelta(minutes=20),
    )
    metrics = calculate_metrics([alert], containment_actions=[action])
    assert metrics.median_containment_seconds == 1200
