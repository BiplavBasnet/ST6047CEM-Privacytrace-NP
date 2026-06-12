"""Deterministic HTTP + PostgreSQL e2e: register viewer → login → limited access → logout."""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.tests.auth_test_utils import auth_headers

pytestmark = [
    pytest.mark.integration,
    pytest.mark.postgres,
    pytest.mark.critical_db,
    pytest.mark.e2e,
]

E2E_EMAIL = "e2e.viewer.register@example.test"
E2E_PASSWORD = "E2eViewerPass123!"


@pytest.fixture
def override_db_session_for_auth_api(db_session):
    from app.dependencies import get_db_session
    from app.main import app

    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def enable_registration(monkeypatch):
    monkeypatch.setenv("SELF_REGISTRATION_ENABLED", "true")
    monkeypatch.setenv("DEFAULT_REGISTRATION_ROLE", "viewer")
    monkeypatch.setenv("EMAIL_VERIFICATION_REQUIRED", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_register_login_dashboard_limits_logout(
    client_no_auth_override,
    enable_registration,
    db_session,
    override_db_session_for_auth_api,
):
    db_session.commit()

    register = client_no_auth_override.post(
        "/auth/register",
        json={
            "full_name": "E2E Viewer",
            "email": E2E_EMAIL,
            "password": E2E_PASSWORD,
            "confirm_password": E2E_PASSWORD,
        },
    )
    assert register.status_code == 201, register.text
    body = register.json()
    assert body["role"] == "viewer"
    assert "password" not in body
    assert "access_token" not in body

    login = client_no_auth_override.post(
        "/auth/login",
        json={"email": E2E_EMAIL, "password": E2E_PASSWORD},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    assert token
    assert E2E_PASSWORD not in login.text

    me = client_no_auth_override.get("/auth/me", headers=auth_headers(token))
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"
    assert me.json()["email"] == E2E_EMAIL

    # Privileged administration controls unavailable to self-registered viewer.
    users = client_no_auth_override.get("/users", headers=auth_headers(token))
    assert users.status_code == 403
    create_user = client_no_auth_override.post(
        "/users",
        headers=auth_headers(token),
        json={
            "name": "Should Fail",
            "email": "should.fail@example.test",
            "role": "admin",
            "password": "ShouldFail123!",
        },
    )
    assert create_user.status_code == 403

    # Read-level dashboard access is unavailable until an organisation admin assigns membership.
    incidents = client_no_auth_override.get("/incidents", headers=auth_headers(token))
    assert incidents.status_code == 403

    logout = client_no_auth_override.post("/auth/logout", headers=auth_headers(token))
    assert logout.status_code == 200
