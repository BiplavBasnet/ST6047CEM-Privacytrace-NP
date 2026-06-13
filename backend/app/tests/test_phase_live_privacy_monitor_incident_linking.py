from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.db.seed_phase2 import seed_phase2
from app.models.detection import Detection
from app.models.evidence_file import EvidenceFile
from app.models.incident import Incident
from app.models.privacy_alert import PrivacyAlert
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

EVENT = {
    "source_type": "api_log",
    "source_name": "wallet-service",
    "source_format": "generic_json",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "environment": "demo",
    "timestamp": "2026-05-20T10:15:00Z",
    "message": "Synthetic phone 9841234567 wallet WALLET-NP-88291 copied into log stream",
    "metadata": {"release_version": "v1.2.0"},
}


@pytest.fixture(autouse=True)
def override_db_session_for_live_monitor_linking(db_session):
    from app.dependencies import get_db_session
    from app.main import app

    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _analyst_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(client_no_auth_override, email="analyst@privacytrace.local", password="AnalystPass123!")


def _create_alert(client_no_auth_override, token) -> str:
    response = client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=EVENT)
    assert response.status_code == 200, response.text
    return response.json()["alert_id"]


def test_create_incident_from_alert_links_masked_supporting_evidence(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)

    response = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    incident_id = body["incident_id"]
    assert incident_id.startswith("INC-LIVE-")

    incident = db_session.scalar(select(Incident).where(Incident.incident_id == incident_id))
    alert = db_session.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id))
    assert incident is not None
    assert alert is not None
    assert incident.status.value == "new"
    assert incident.status.value != "confirmed_incident"
    assert alert.linked_incident_id == incident_id
    assert alert.status == "linked_to_incident"
    assert alert.human_review_required is True
    assert alert.evidence_id is not None

    evidence = db_session.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == alert.evidence_id))
    detections = db_session.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    assert evidence is not None
    assert evidence.file_hash == alert.raw_event_hash
    assert detections
    for detection in detections:
        assert detection.masked_value
        assert "9841234567" not in detection.masked_value
        assert "WALLET-NP-88291" not in detection.masked_value


def test_link_alert_to_existing_incident(client_no_auth_override, demo_users, db_session):
    seed_phase2(db_session)
    db_session.commit()
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)

    response = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "link_existing", "incident_id": "INC-SEED-001"},
    )
    assert response.status_code == 200, response.text
    alert = db_session.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id))
    assert alert is not None
    assert alert.linked_incident_id == "INC-SEED-001"
    assert alert.status == "linked_to_incident"


def test_created_incident_trace_works_and_contains_no_raw_values(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)
    linked = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    incident_id = linked.json()["incident_id"]

    response = client_no_auth_override.get(f"/incidents/{incident_id}/trace", headers=auth_headers(token))
    assert response.status_code == 200, response.text
    blob = json.dumps(response.json())
    assert "9841234567" not in blob
    assert "WALLET-NP-88291" not in blob
    assert response.json()["human_review_required"] is True


def test_final_report_for_live_alert_incident_is_privacy_safe(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)
    linked = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    incident_id = linked.json()["incident_id"]

    response = client_no_auth_override.get(
        f"/reports/incidents/{incident_id}/final-report.json",
        headers=auth_headers(token),
    )
    assert response.status_code == 200, response.text
    blob = json.dumps(response.json())
    assert "9841234567" not in blob
    assert "WALLET-NP-88291" not in blob
    assert response.json()["guarded_explanation"]["human_review_required"] is True
    live_summary = response.json()["live_monitor_summary"]
    assert live_summary["source"] == "Live Monitor"
    assert live_summary["linked_alert_count"] == 1
    assert live_summary["evidence_strength"] in {"weak", "medium"}
    assert live_summary["alerts"][0]["alert_id"] == alert_id


def test_live_retest_event_records_fixed_log_and_supports_verification(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)
    linked = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    incident_id = linked.json()["incident_id"]

    analysed = client_no_auth_override.post(
        "/incidents/analyse",
        headers=auth_headers(token),
        json={"incident_id": incident_id, "force": True},
    )
    assert analysed.status_code == 200, analysed.text

    review = client_no_auth_override.post(
        f"/incidents/{incident_id}/review",
        headers=auth_headers(token),
        json={
            "decision": "approved",
            "reason": "Masked live evidence supports a human-owned remediation action.",
            "comment": "Masked evidence reviewed for remediation.",
        },
    )
    assert review.status_code == 200, review.text

    remediation = client_no_auth_override.post(
        f"/incidents/{incident_id}/remediation-actions",
        headers=auth_headers(token),
        json={
            "action_type": "redaction_rule_update",
            "action_description": "Update the reviewed live-event redaction rule.",
            "affected_component": "wallet logging middleware",
            "assigned_owner": "wallet platform team",
            "status": "awaiting_retest",
            "priority": "high",
            "retest_required": True,
        },
    )
    assert remediation.status_code == 200, remediation.text

    retest = client_no_auth_override.post(
        f"/live-monitor/incidents/{incident_id}/retest-event",
        headers=auth_headers(token),
        json={},
    )
    assert retest.status_code == 200, retest.text
    body = retest.json()
    assert body["retest_source"] == "Live Monitor retest event"
    assert body["service_endpoint_match"] is True
    assert body["sensitive_value_still_appears"] is False
    evidence = db_session.scalar(
        select(EvidenceFile).where(EvidenceFile.evidence_id == body["evidence_id"])
    )
    assert evidence is not None
    assert evidence.evidence_type.value == "fixed_log"
    assert evidence.linked_incident_id == incident_id

    verified = client_no_auth_override.post(
        f"/incidents/{incident_id}/verify-fix",
        headers=auth_headers(token),
        json={"retest_evidence_ids": [body["evidence_id"]]},
    )
    assert verified.status_code == 422, verified.text


def test_dismiss_does_not_delete_alert(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)
    response = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/dismiss",
        headers=auth_headers(token),
        json={"reason": "synthetic false positive"},
    )
    assert response.status_code == 200, response.text
    alert = db_session.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id))
    assert alert is not None
    assert alert.status == "dismissed_false_positive"


def test_linked_alert_cannot_be_relinked_or_dismissed(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    alert_id = _create_alert(client_no_auth_override, token)
    linked = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    assert linked.status_code == 200, linked.text

    relink = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    dismiss = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/dismiss",
        headers=auth_headers(token),
        json={"reason": "Reviewed after incident linkage"},
    )
    assert relink.status_code == 409
    assert dismiss.status_code == 409
    assert db_session.scalar(select(Incident).where(Incident.incident_id == linked.json()["incident_id"]))

