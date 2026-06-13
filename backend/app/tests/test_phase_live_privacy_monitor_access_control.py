from __future__ import annotations

import pytest

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
    "message": "Synthetic phone 9841234567 copied into log",
    "metadata": {},
}


@pytest.fixture(autouse=True)
def override_db_session_for_live_monitor_access(db_session):
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


def _token(client_no_auth_override, demo_users, db_session, role: str) -> str:
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


def _create_alert(client_no_auth_override, demo_users, db_session) -> str:
    token = _token(client_no_auth_override, demo_users, db_session, "security_analyst")
    response = client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=EVENT)
    assert response.status_code == 200, response.text
    return response.json()["alert_id"]


def test_unauthenticated_requests_are_rejected(client_no_auth_override):
    assert client_no_auth_override.get("/live-monitor/status").status_code == 401
    assert client_no_auth_override.post("/live-monitor/events", json=EVENT).status_code == 401


def test_allowed_roles_can_view_status(client_no_auth_override, demo_users, db_session):
    for role in ("admin", "security_analyst", "devsecops_engineer", "auditor"):
        token = _token(client_no_auth_override, demo_users, db_session, role)
        response = client_no_auth_override.get("/live-monitor/status", headers=auth_headers(token))
        assert response.status_code == 200, role


def test_viewer_and_developer_cannot_view_live_monitor(client_no_auth_override, demo_users, db_session):
    for role in ("viewer", "developer"):
        token = _token(client_no_auth_override, demo_users, db_session, role)
        response = client_no_auth_override.get("/live-monitor/status", headers=auth_headers(token))
        assert response.status_code == 403, role


def test_wrong_role_cannot_start_or_stop_monitor(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session, "auditor")
    start = client_no_auth_override.post("/live-monitor/start", headers=auth_headers(token), json={"mode": "http_ingestion"})
    stop = client_no_auth_override.post("/live-monitor/stop", headers=auth_headers(token))
    assert start.status_code == 403
    assert stop.status_code == 403


def test_wrong_role_cannot_ingest_event(client_no_auth_override, demo_users, db_session):
    token = _token(client_no_auth_override, demo_users, db_session, "auditor")
    response = client_no_auth_override.post("/live-monitor/events", headers=auth_headers(token), json=EVENT)
    assert response.status_code == 403


def test_wrong_role_cannot_create_incident_from_alert(client_no_auth_override, demo_users, db_session):
    alert_id = _create_alert(client_no_auth_override, demo_users, db_session)
    token = _token(client_no_auth_override, demo_users, db_session, "auditor")
    response = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    assert response.status_code == 403


def test_dismiss_alert_limited_to_allowed_roles(client_no_auth_override, demo_users, db_session):
    alert_id = _create_alert(client_no_auth_override, demo_users, db_session)
    auditor = _token(client_no_auth_override, demo_users, db_session, "auditor")
    denied = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/dismiss",
        headers=auth_headers(auditor),
        json={"reason": "not enough support"},
    )
    assert denied.status_code == 403

    analyst = _token(client_no_auth_override, demo_users, db_session, "security_analyst")
    allowed = client_no_auth_override.post(
        f"/live-monitor/alerts/{alert_id}/dismiss",
        headers=auth_headers(analyst),
        json={"reason": "masked false positive in synthetic stream"},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["status"] == "dismissed_false_positive"
