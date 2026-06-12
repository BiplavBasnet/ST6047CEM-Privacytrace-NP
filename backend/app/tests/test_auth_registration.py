"""Public self-registration and auth registration policy tests (PostgreSQL)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.enums import UserRole
from app.models.user import User
from app.services import audit_service, password_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = [
    pytest.mark.integration,
    pytest.mark.postgres,
    pytest.mark.critical_db,
]

STRONG_PASSWORD = "SyntheticViewer123!"


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
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


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


def _register_payload(**overrides):
    payload = {
        "full_name": "Synthetic Analyst",
        "email": "synthetic.viewer@example.test",
        "password": STRONG_PASSWORD,
        "confirm_password": STRONG_PASSWORD,
    }
    payload.update(overrides)
    return payload


def test_registration_status_endpoint(client_no_auth_override, enable_registration, db_session):
    db_session.commit()
    response = client_no_auth_override.get("/auth/registration-status")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["default_role"] == "viewer"
    assert body["email_verification_required"] is False


def test_registration_succeeds_and_user_can_login(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    response = client_no_auth_override.post("/auth/register", json=_register_payload())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["email"] == "synthetic.viewer@example.test"
    assert body["role"] == "viewer"
    assert "password" not in body
    assert "password_hash" not in response.text
    assert "access_token" not in body

    token = login(
        client_no_auth_override,
        email="synthetic.viewer@example.test",
        password=STRONG_PASSWORD,
    )
    me = client_no_auth_override.get("/auth/me", headers=auth_headers(token))
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"


def test_email_normalisation_on_register_and_login(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/register",
        json=_register_payload(email="  Mixed.Case@Example.TEST "),
    )
    assert response.status_code == 201, response.text
    assert response.json()["email"] == "mixed.case@example.test"

    token = login(
        client_no_auth_override,
        email="Mixed.Case@Example.TEST",
        password=STRONG_PASSWORD,
    )
    assert token


def test_duplicate_email_rejected(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    assert (
        client_no_auth_override.post("/auth/register", json=_register_payload()).status_code
        == 201
    )
    duplicate = client_no_auth_override.post("/auth/register", json=_register_payload())
    assert duplicate.status_code == 409


def test_duplicate_email_case_variant_rejected(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    assert (
        client_no_auth_override.post(
            "/auth/register", json=_register_payload(email="dup@example.test")
        ).status_code
        == 201
    )
    duplicate = client_no_auth_override.post(
        "/auth/register",
        json=_register_payload(email="DUP@example.test", full_name="Other"),
    )
    assert duplicate.status_code == 409


def test_invalid_email_rejected(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/register",
        json=_register_payload(email="not-an-email"),
    )
    assert response.status_code == 422


def test_weak_password_rejected(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/register",
        json=_register_payload(password="weakpass", confirm_password="weakpass"),
    )
    assert response.status_code == 422
    assert "weakpass" not in response.text


def test_password_mismatch_rejected(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/register",
        json=_register_payload(confirm_password="DifferentPass123!"),
    )
    assert response.status_code == 422


def test_password_is_hashed_not_plaintext(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    assert (
        client_no_auth_override.post("/auth/register", json=_register_payload()).status_code
        == 201
    )
    user = db_session.scalar(
        select(User).where(User.email == "synthetic.viewer@example.test")
    )
    assert user is not None
    assert user.password_hash
    assert STRONG_PASSWORD not in user.password_hash
    assert password_service.verify_password(STRONG_PASSWORD, user.password_hash)


def test_role_injection_rejected(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    payload = _register_payload(email="inject@example.test")
    payload["role"] = "admin"
    response = client_no_auth_override.post("/auth/register", json=payload)
    assert response.status_code == 422
    user = db_session.scalar(select(User).where(User.email == "inject@example.test"))
    assert user is None


def test_default_role_is_viewer(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/register",
        json=_register_payload(email="rolecheck@example.test"),
    )
    assert response.status_code == 201
    assert response.json()["role"] == UserRole.VIEWER.value
    user = db_session.scalar(select(User).where(User.email == "rolecheck@example.test"))
    assert user is not None
    assert user.role == UserRole.VIEWER


def test_disabled_registration_enforced(
    client_no_auth_override, monkeypatch, db_session, override_db_session_for_auth_api
):
    monkeypatch.setenv("SELF_REGISTRATION_ENABLED", "false")
    get_settings.cache_clear()
    try:
        db_session.commit()
        response = client_no_auth_override.post("/auth/register", json=_register_payload())
        assert response.status_code == 403
        status = client_no_auth_override.get("/auth/registration-status")
        assert status.json()["enabled"] is False
    finally:
        get_settings.cache_clear()


def test_registration_audit_has_no_secrets(
    client_no_auth_override, enable_registration, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    assert (
        client_no_auth_override.post("/auth/register", json=_register_payload()).status_code
        == 201
    )
    entry = db_session.scalars(
        select(AuditLog)
        .where(AuditLog.action == audit_service.ACTION_REGISTRATION_SUCCEEDED)
        .order_by(AuditLog.id.desc())
    ).first()
    assert entry is not None
    blob = json.dumps(entry.details or {})
    assert STRONG_PASSWORD not in blob
    assert "access_token" not in blob
    assert "$pbkdf2" not in blob.lower()
    assert "password_hash" not in blob.lower()
    # Audit may include email; must not include the submitted password field value keyed as password.
    assert '"password"' not in blob.lower()


def test_existing_login_still_works(
    client_no_auth_override, demo_users, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    assert token


def test_viewer_rbac_unchanged_after_registration_module(
    client_no_auth_override, demo_users, db_session, override_db_session_for_auth_api
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )
    denied = client_no_auth_override.get("/users", headers=auth_headers(token))
    assert denied.status_code == 403
