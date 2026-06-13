"""Targeted onboarding hardening: bootstrap, method, SMTP/demo tokens, suspend, reset."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.enums import OrganisationStatus, OrganisationVerificationStatus, UserRole
from app.models.organisation import DeploymentSetup, Organisation, OrganisationMembership
from app.models.user import User
from app.services import (
    email_delivery_service,
    organisation_access_service as org_access,
    organisation_verification_policy_service as policy,
)
from app.tests.auth_test_utils import auth_headers, login

pytestmark = [pytest.mark.integration, pytest.mark.postgres, pytest.mark.critical_db]

ADMIN_PASSWORD = "OrgAdminPass123!"
BOOTSTRAP_TOKEN = "test-bootstrap-token-for-ci"


@pytest.fixture
def override_db(db_session):
    from app.dependencies import get_db_session
    from app.main import app

    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def client_no_auth(client):
    from app.dependencies.auth_dependencies import get_current_user
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _setup_payload(**overrides):
    payload = {
        "organisation_name": "ABC Wallet",
        "administrator_full_name": "Ada Admin",
        "email": "ada.admin@abc.test",
        "password": ADMIN_PASSWORD,
        "confirm_password": ADMIN_PASSWORD,
        "bootstrap_token": BOOTSTRAP_TOKEN,
    }
    payload.update(overrides)
    return payload


def _activate(db_session, email="ada.admin@abc.test"):
    org = db_session.scalar(select(Organisation))
    user = db_session.scalar(select(User).where(User.email == email))
    org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
    org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
    org.website_domain = "abc.test"
    user.admin_email_verified = True
    policy.activate_verified_organisation(db_session, org, actor_id=user.id)
    db_session.commit()
    return org, user


def test_bootstrap_required_and_consumed(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    status = client_no_auth.get("/setup/status").json()
    assert status["bootstrap_required"] is True
    assert client_no_auth.post(
        "/setup/organisation", json=_setup_payload(bootstrap_token="wrong-token-value")
    ).status_code == 403
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    setup = db_session.get(DeploymentSetup, 1)
    assert setup is not None and setup.bootstrap_consumed_at is not None
    assert client_no_auth.post(
        "/setup/organisation",
        json=_setup_payload(email="other@abc.test", organisation_name="Other"),
    ).status_code == 409


def test_manual_review_stays_until_operator(db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings

    get_settings.cache_clear()
    org, user, _ = org_access.complete_setup(
        db_session,
        organisation_name="ABC Wallet",
        admin_name="Ada",
        email="ada.admin@abc.test",
        password=ADMIN_PASSWORD,
        bootstrap_token=BOOTSTRAP_TOKEN,
    )
    org.overall_verification_status = OrganisationVerificationStatus.MANUAL_REVIEW
    org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
    org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
    overall = policy.recompute_and_maybe_activate(db_session, org, actor_id=user.id)
    assert overall == OrganisationVerificationStatus.MANUAL_REVIEW
    assert org.status != OrganisationStatus.ACTIVE or org.overall_verification_status == OrganisationVerificationStatus.MANUAL_REVIEW
    membership = db_session.scalar(select(OrganisationMembership))
    assert membership.status.value == "pending"


def test_pan_mask_in_public_status(db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings

    get_settings.cache_clear()
    org, _, _ = org_access.complete_setup(
        db_session,
        organisation_name="ABC Wallet",
        admin_name="Ada",
        email="ada.admin@abc.test",
        password=ADMIN_PASSWORD,
        bootstrap_token=BOOTSTRAP_TOKEN,
        pan_number="123456789",
    )
    public = policy.verification_status_public(org)
    assert public["pan_masked"] == "*****6789"
    assert "123456789" not in str(public)


def test_identity_invalidation_blocks_invites(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    org, user = _activate(db_session)
    token = login(client_no_auth, email=user.email, password=ADMIN_PASSWORD)
    policy.invalidate_identity_change(org, field="legal_name")
    db_session.commit()
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "x@abc.test", "role": "viewer"},
    )
    assert invite.status_code == 403


def test_suspend_blocks_invites(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings
    from app.services import user_service

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    org, user = _activate(db_session)
    user_service.create_user(
        db_session,
        name="Platform Op",
        email="op@privacytrace.local",
        role=UserRole.PLATFORM_ADMIN,
        password="PlatformOpPass123!",
    )
    db_session.commit()
    op_token = login(client_no_auth, email="op@privacytrace.local", password="PlatformOpPass123!")
    suspended = client_no_auth.post(
        "/organisation/suspend",
        headers=auth_headers(op_token),
        json={"reason": "Security hold for investigation"},
    )
    assert suspended.status_code == 200
    assert suspended.json()["organisation_operational_status"] == "suspended"
    admin_token = login(client_no_auth, email=user.email, password=ADMIN_PASSWORD)
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "y@abc.test", "role": "viewer"},
    )
    assert invite.status_code == 403


def test_password_reset_demo_token_and_consume(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    monkeypatch.setenv("SMTP_ENABLED", "false")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    _activate(db_session)
    requested = client_no_auth.post(
        "/auth/password-reset/request",
        json={"email": "ada.admin@abc.test"},
    )
    assert requested.status_code == 200
    body = requested.json()
    assert body["demo_simulated"] is True
    assert body["demo_reset_token"]
    confirm = client_no_auth.post(
        "/auth/password-reset/confirm",
        json={
            "token": body["demo_reset_token"],
            "password": "NewAdminPass123!",
            "confirm_password": "NewAdminPass123!",
        },
    )
    assert confirm.status_code == 200
    assert login(client_no_auth, email="ada.admin@abc.test", password="NewAdminPass123!")


def test_demo_token_exposure_gated_when_smtp_on(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SMTP_ENABLED", "true")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    from app.config import get_settings

    get_settings.cache_clear()
    assert email_delivery_service.demo_token_exposure_allowed() is False


def test_viewer_cannot_mutate_company_verification(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    org, user = _activate(db_session)
    admin_token = login(client_no_auth, email=user.email, password=ADMIN_PASSWORD)
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "viewer.emp@abc.test", "role": "viewer"},
    )
    assert invite.status_code == 201, invite.text
    raw = invite.json()["invite_token"]
    accepted = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Viewer Emp",
            "email": "viewer.emp@abc.test",
            "password": "EmployeePass123!",
            "confirm_password": "EmployeePass123!",
            "invite_token": raw,
        },
    )
    assert accepted.status_code == 201, accepted.text
    viewer_token = login(client_no_auth, email="viewer.emp@abc.test", password="EmployeePass123!")
    denied = client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(viewer_token),
        json={"legal_name": org.legal_name or org.name, "registration_number": "123456"},
    )
    assert denied.status_code == 403


def test_suspended_org_cannot_mutate_company_verification(
    client_no_auth, override_db, db_session, monkeypatch
):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings
    from app.services import user_service

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    org, user = _activate(db_session)
    user_service.create_user(
        db_session,
        name="Platform Op",
        email="op-verify@privacytrace.local",
        role=UserRole.PLATFORM_ADMIN,
        password="PlatformOpPass123!",
    )
    db_session.commit()
    op_token = login(
        client_no_auth, email="op-verify@privacytrace.local", password="PlatformOpPass123!"
    )
    assert client_no_auth.post(
        "/organisation/suspend",
        headers=auth_headers(op_token),
        json={"reason": "Security hold for investigation"},
    ).status_code == 200
    admin_token = login(client_no_auth, email=user.email, password=ADMIN_PASSWORD)
    denied = client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(admin_token),
        json={"legal_name": org.legal_name or org.name, "registration_number": "123456"},
    )
    assert denied.status_code == 403


def test_password_change_invalidates_existing_session(
    client_no_auth, override_db, db_session, monkeypatch
):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    _, user = _activate(db_session)
    token = login(client_no_auth, email=user.email, password=ADMIN_PASSWORD)
    changed = client_no_auth.patch(
        f"/users/{user.id}",
        headers=auth_headers(token),
        json={"password": "NewerAdminPass123!"},
    )
    assert changed.status_code == 200, changed.text
    stale = client_no_auth.get("/auth/me", headers=auth_headers(token))
    assert stale.status_code == 401
    assert login(client_no_auth, email=user.email, password="NewerAdminPass123!")


def test_admin_email_change_invalidates_email_verification(
    client_no_auth, override_db, db_session, monkeypatch
):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    monkeypatch.setenv("SMTP_ENABLED", "false")
    from app.config import get_settings
    from app.models.enums import OrganisationVerificationStatus

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    org, user = _activate(db_session)
    token = login(client_no_auth, email=user.email, password=ADMIN_PASSWORD)
    issued = client_no_auth.post(
        "/setup/verification/email/issue",
        headers=auth_headers(token),
    )
    assert issued.status_code == 200, issued.text
    old_email_token = issued.json()["verify_token"]
    assert old_email_token
    changed = client_no_auth.patch(
        f"/users/{user.id}",
        headers=auth_headers(token),
        json={"email": "ada.replaced@abc.test"},
    )
    assert changed.status_code == 200, changed.text
    db_session.refresh(org)
    db_session.refresh(user)
    assert user.admin_email_verified is False
    assert org.admin_email_verification_status != OrganisationVerificationStatus.VERIFIED
    fresh = login(client_no_auth, email="ada.replaced@abc.test", password=ADMIN_PASSWORD)
    confirm = client_no_auth.post(
        "/setup/verification/email/confirm",
        headers=auth_headers(fresh),
        json={"token": old_email_token},
    )
    assert confirm.status_code == 400


def test_password_reset_replay_and_replacement(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN)
    monkeypatch.setenv("SMTP_ENABLED", "false")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    _activate(db_session)
    first = client_no_auth.post(
        "/auth/password-reset/request", json={"email": "ada.admin@abc.test"}
    ).json()
    token_a = first["demo_reset_token"]
    second = client_no_auth.post(
        "/auth/password-reset/request", json={"email": "ada.admin@abc.test"}
    ).json()
    token_b = second["demo_reset_token"]
    assert token_a and token_b and token_a != token_b
    replay_a = client_no_auth.post(
        "/auth/password-reset/confirm",
        json={
            "token": token_a,
            "password": "ReplacedPass123!",
            "confirm_password": "ReplacedPass123!",
        },
    )
    assert replay_a.status_code == 400
    confirm_b = client_no_auth.post(
        "/auth/password-reset/confirm",
        json={
            "token": token_b,
            "password": "ReplacedPass123!",
            "confirm_password": "ReplacedPass123!",
        },
    )
    assert confirm_b.status_code == 200
    replay_b = client_no_auth.post(
        "/auth/password-reset/confirm",
        json={
            "token": token_b,
            "password": "ReplayPass1234!",
            "confirm_password": "ReplayPass1234!",
        },
    )
    assert replay_b.status_code == 400


def test_reset_and_email_consume_lock_current_row():
    import inspect

    from app.services import organisation_email_verification_service, password_reset_service

    assert "with_for_update" in inspect.getsource(password_reset_service.consume_password_reset)
    assert "with_for_update" in inspect.getsource(
        organisation_email_verification_service.consume_email_verification
    )
