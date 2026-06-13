from __future__ import annotations

import pytest

from app.tests.ai_remediation_test_helpers import (
    clear_ai_settings,
    enable_mock_ai,
    role_token,
    seed_ai_incident,
)
from app.tests.auth_test_utils import auth_headers, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db")


@pytest.fixture(autouse=True)
def ai_settings_cleanup(monkeypatch):
    clear_ai_settings(monkeypatch)
    yield
    clear_ai_settings(monkeypatch)


@pytest.fixture(autouse=True)
def override_db_session_for_ai_remediation(db_session):
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


def test_unauthenticated_requests_are_rejected(client_no_auth_override):
    assert client_no_auth_override.get("/ai-remediation/status").status_code == 401
    assert client_no_auth_override.post("/ai-remediation/incidents/INC-AI-001/suggest").status_code == 401


def test_allowed_reader_roles_can_view_status(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    for role in ("admin", "security_analyst", "devsecops_engineer", "auditor"):
        token = role_token(client_no_auth_override, db_session, role)
        response = client_no_auth_override.get(
            "/ai-remediation/status",
            headers=auth_headers(token),
        )
        assert response.status_code == 200, role


def test_viewer_and_developer_cannot_read_ai_remediation(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    for role in ("viewer", "developer"):
        token = role_token(client_no_auth_override, db_session, role)
        response = client_no_auth_override.get(
            "/ai-remediation/status",
            headers=auth_headers(token),
        )
        assert response.status_code == 403, role


def test_generate_and_review_allowed_for_admin_analyst_and_devsecops(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    for index, role in enumerate(("admin", "security_analyst", "devsecops_engineer"), start=1):
        incident_id = seed_ai_incident(db_session, incident_id=f"INC-AI-GEN-{index}")
        token = role_token(client_no_auth_override, db_session, role)
        generated = client_no_auth_override.post(
            f"/ai-remediation/incidents/{incident_id}/suggest",
            headers=auth_headers(token),
        )
        assert generated.status_code == 200, role
        suggestion_id = generated.json()["suggestion"]["suggestion_id"]
        accepted = client_no_auth_override.post(
            f"/ai-remediation/suggestions/{suggestion_id}/accept",
            headers=auth_headers(token),
            json={"reviewer_notes": f"Accepted by {role} using masked evidence", "create_remediation_action": False},
        )
        assert accepted.status_code == 200, role


def test_auditor_is_read_only_for_ai_remediation(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-AUD")
    analyst = role_token(client_no_auth_override, db_session, "security_analyst")
    generated = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(analyst),
    )
    assert generated.status_code == 200, generated.text
    suggestion_id = generated.json()["suggestion"]["suggestion_id"]

    auditor = role_token(client_no_auth_override, db_session, "auditor")
    can_list = client_no_auth_override.get(
        f"/ai-remediation/incidents/{incident_id}/suggestions",
        headers=auth_headers(auditor),
    )
    assert can_list.status_code == 200

    denied_generate = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(auditor),
    )
    denied_accept = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/accept",
        headers=auth_headers(auditor),
        json={"reviewer_notes": "read only role", "create_remediation_action": False},
    )
    assert denied_generate.status_code == 403
    assert denied_accept.status_code == 403


def test_viewer_cannot_approve_remediation(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-VIEWER-APPROVE")
    analyst = role_token(client_no_auth_override, db_session, "security_analyst")
    generated = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(analyst),
    )
    assert generated.status_code == 200, generated.text
    suggestion_id = generated.json()["suggestion"]["suggestion_id"]

    viewer = role_token(client_no_auth_override, db_session, "viewer")
    denied = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/accept",
        headers=auth_headers(viewer),
        json={"reviewer_notes": "viewer must not approve", "create_remediation_action": False},
    )
    assert denied.status_code == 403
