from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.db.seed_phase2 import seed_phase2
from app.models.audit_log import AuditLog
from app.models.privacy_alert import PrivacyAlert
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

SAFE_EVENT = {
    "source_type": "api_log",
    "source_name": "wallet-service",
    "source_format": "generic_json",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "environment": "demo",
    "timestamp": "2026-05-20T10:15:00Z",
    "message": "Synthetic request completed with no sensitive fields",
    "metadata": {"release_version": "v1.2.0"},
}

PHONE_EVENT = {
    **SAFE_EVENT,
    "message": "Synthetic live event phone=9841234567",
}


@pytest.fixture(autouse=True)
def override_db_session_for_live_monitor(db_session):
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


def _token(client_no_auth_override, demo_users, db_session, role="security_analyst") -> str:
    db_session.commit()
    spec = {
        "admin": ("admin@privacytrace.local", "AdminPass123!"),
        "security_analyst": ("analyst@privacytrace.local", "AnalystPass123!"),
        "devsecops_engineer": ("devsecops@privacytrace.local", "DevSecOpsPass123!"),
        "auditor": ("auditor@privacytrace.local", "AuditorPass123!"),
        "viewer": ("viewer@privacytrace.local", "ViewerPass123!"),
        "developer": ("developer@privacytrace.local", "DeveloperPass123!"),
    }[role]
    return login(client_no_auth_override, email=spec[0], password=spec[1])


def test_live_monitor_router_is_registered(client_no_auth_override):
    response = client_no_auth_override.get("/live-monitor/status")
    assert response.status_code == 401


def test_status_endpoint_works(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.get("/live-monitor/status", headers=auth_headers(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["supported_input_modes"]
    assert body["safety_status"] in {"safe", "manual_review_required"}


def test_start_and_stop_work_for_allowed_role(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    start = client_no_auth_override.post(
        "/live-monitor/start",
        headers=auth_headers(token),
        json={"mode": "http_ingestion", "source_name": "wallet-service", "environment": "demo", "safe_mode": True},
    )
    assert start.status_code == 200, start.text
    assert start.json()["running"] is True

    stop = client_no_auth_override.post("/live-monitor/stop", headers=auth_headers(token))
    assert stop.status_code == 200, stop.text
    assert stop.json()["running"] is False


def test_stopped_monitor_rejects_event_ingestion(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    client_no_auth_override.post("/live-monitor/stop", headers=auth_headers(token))

    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json=PHONE_EVENT,
    )

    assert response.status_code == 409
    assert "stopped" in response.json()["detail"].lower()
    assert db_session.scalar(select(PrivacyAlert).limit(1)) is None


def test_generic_json_event_without_sensitive_value_creates_no_alert(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=SAFE_EVENT)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "no_alert"
    assert body["alert_id"] is None
    assert db_session.scalar(select(PrivacyAlert).limit(1)) is None


def test_event_with_synthetic_phone_creates_masked_alert(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=PHONE_EVENT)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "alert_created"
    assert body["alert_id"].startswith("LPA-")
    assert "phone_number" in body["sensitive_types"]
    assert "98******67" in json.dumps(body)
    assert "9841234567" not in json.dumps(body)


def test_syslog_like_event_ingestion_creates_alert(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    event = {
        **SAFE_EVENT,
        "source_format": "syslog_like",
        "message": "May 20 wallet-service app: wallet WALLET-NP-88291 appeared in copied log stream",
    }
    response = client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=event)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "alert_created"
    assert "wallet_[masked]" in json.dumps(body)
    assert "WALLET-NP-88291" not in json.dumps(body)


def test_batch_ingestion_returns_per_item_status(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    body = {"events": [SAFE_EVENT, PHONE_EVENT]}
    response = client_no_auth_override.post("/live-monitor/events/batch", headers=auth_headers(token), json=body)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 2
    assert payload["no_alert_count"] == 1
    assert payload["alert_count"] == 1


def test_test_event_creates_safe_demo_alert(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post("/live-monitor/test-event", headers=auth_headers(token))
    assert response.status_code == 200, response.text
    blob = json.dumps(response.json())
    assert "alert_created" in blob
    assert "9841234567" not in blob
    assert "WALLET-NP-88291" not in blob
    assert "TXN-NP-2026-77881" not in blob


def test_live_monitor_audits_start_stop_and_alert(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session)
    client_no_auth_override.post("/live-monitor/start", headers=auth_headers(token), json={"mode": "http_ingestion"})
    client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=PHONE_EVENT)
    client_no_auth_override.post("/live-monitor/stop", headers=auth_headers(token))
    actions = {row.action for row in db_session.scalars(select(AuditLog)).all()}
    assert "live_monitor_started" in actions
    assert "live_privacy_alert_created" in actions
    assert "live_monitor_stopped" in actions


def test_existing_evidence_load_sample_still_works(client_no_auth_override, demo_users, db_session):
    seed_phase2(db_session)
    db_session.commit()
    token = _token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/evidence/load-sample",
        headers=auth_headers(token),
        json={"scenario": "scenario_1"},
    )
    assert response.status_code in (200, 201), response.text
