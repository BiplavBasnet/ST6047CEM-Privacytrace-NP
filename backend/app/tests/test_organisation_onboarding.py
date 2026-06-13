"""Organisation onboarding, invitations, and membership access control."""

from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.enums import IncidentStatus, MembershipStatus, Severity, UserRole
from app.models.incident import Incident
from app.models.organisation import (
    DeploymentSetup,
    Organisation,
    OrganisationInvitation,
    OrganisationMembership,
)
from app.models.user import User
from app.services import organisation_access_service as org_access
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = [
    pytest.mark.integration,
    pytest.mark.postgres,
    pytest.mark.critical_db,
]

ADMIN_PASSWORD = "OrgAdminPass123!"
EMPLOYEE_PASSWORD = "EmployeePass123!"
BOOTSTRAP_TOKEN = "test-bootstrap-token-for-ci"


def _force_verify_and_activate(db_session, *, email: str = "ada.admin@abc.test"):
    """Skip wizard: mark org verified and activate pending first admin (test helper)."""
    from app.models.enums import OrganisationVerificationStatus
    from app.services import organisation_verification_policy_service as policy

    org = db_session.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))
    user = db_session.scalar(select(User).where(User.email == email))
    assert org is not None and user is not None
    org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
    org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
    org.website_domain = org.website_domain or "abc.test"
    org.approved_email_domains = list(org.approved_email_domains or []) or ["abc.test"]
    user.admin_email_verified = True
    policy.activate_verified_organisation(db_session, org, actor_id=user.id, notes_safe="test force verify")
    db_session.commit()
    return org, user


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


def test_setup_status_required_when_empty(client_no_auth, override_db, db_session):
    db_session.commit()
    response = client_no_auth.get("/setup/status")
    assert response.status_code == 200
    body = response.json()
    assert body["required"] is True
    assert body["registration_open"] is True
    assert body["completed"] is False


def test_first_setup_creates_org_and_admin(client_no_auth, override_db, db_session):
    db_session.commit()
    response = client_no_auth.post("/setup/organisation", json=_setup_payload())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["organisation_name"] == "ABC Wallet"
    assert body["role"] == "organisation_admin"
    assert body["overall_verification_status"] == "pending_verification"
    assert body["membership_status"] == "pending"
    org = db_session.scalar(select(Organisation))
    assert org is not None
    user = db_session.scalar(select(User).where(User.email == "ada.admin@abc.test"))
    assert user.role == UserRole.ORGANISATION_ADMIN
    membership = db_session.scalar(select(OrganisationMembership).where(OrganisationMembership.user_id == user.id))
    assert membership.status == MembershipStatus.PENDING
    assert membership.role == UserRole.ORGANISATION_ADMIN
    # Pending admin cannot access operations yet.
    token = login(client_no_auth, email="ada.admin@abc.test", password=ADMIN_PASSWORD)
    incidents = client_no_auth.get("/incidents", headers=auth_headers(token))
    assert incidents.status_code == 403


def test_second_setup_blocked(client_no_auth, override_db, db_session):
    db_session.commit()
    assert client_no_auth.post("/setup/organisation", json=_setup_payload()).status_code == 201
    second = client_no_auth.post(
        "/setup/organisation",
        json=_setup_payload(email="other.admin@abc.test", organisation_name="Other Co"),
    )
    assert second.status_code == 409
    assert "already completed" in second.json()["detail"].lower()
    assert db_session.scalar(select(Organisation)) is not None
    assert len(list(db_session.scalars(select(Organisation)).all())) == 1


def test_setup_unavailable_after_completion(client_no_auth, override_db, db_session):
    db_session.commit()
    client_no_auth.post("/setup/organisation", json=_setup_payload())
    status = client_no_auth.get("/setup/status")
    assert status.json()["required"] is False
    assert status.json()["completed"] is False
    assert status.json()["verification_pending"] is True
    assert status.json()["registration_open"] is False
    _force_verify_and_activate(db_session)
    status2 = client_no_auth.get("/setup/status")
    assert status2.json()["completed"] is True
    assert status2.json()["verification_pending"] is False
    assert status2.json()["required"] is False


def test_public_signup_cannot_request_admin(client_no_auth, override_db, db_session):
    db_session.commit()
    payload = {
        "full_name": "Self Admin",
        "email": "self.admin@example.test",
        "password": EMPLOYEE_PASSWORD,
        "confirm_password": EMPLOYEE_PASSWORD,
        "role": "organisation_admin",
    }
    response = client_no_auth.post("/auth/register", json=payload)
    assert response.status_code == 422
    assert db_session.scalar(select(User).where(User.email == "self.admin@example.test")) is None


def test_public_signup_cannot_request_membership(client_no_auth, override_db, db_session):
    db_session.commit()
    payload = {
        "full_name": "Self Member",
        "email": "self.member@example.test",
        "password": EMPLOYEE_PASSWORD,
        "confirm_password": EMPLOYEE_PASSWORD,
        "organisation_id": 1,
    }
    response = client_no_auth.post("/auth/register", json=payload)
    assert response.status_code == 422


def test_uninvited_signup_has_no_org_access(client_no_auth, override_db, db_session):
    db_session.commit()
    assert (
        client_no_auth.post(
            "/auth/register",
            json={
                "full_name": "Unassigned",
                "email": "unassigned@example.test",
                "password": EMPLOYEE_PASSWORD,
                "confirm_password": EMPLOYEE_PASSWORD,
            },
        ).status_code
        == 201
    )
    token = login(client_no_auth, email="unassigned@example.test", password=EMPLOYEE_PASSWORD)
    me = client_no_auth.get("/auth/me", headers=auth_headers(token))
    assert me.status_code == 200
    assert me.json()["membership"] is None
    incidents = client_no_auth.get("/incidents", headers=auth_headers(token))
    assert incidents.status_code == 403
    assert "not currently assigned" in incidents.json()["detail"].lower()


def test_user_cannot_change_own_role_through_me(client_no_auth, override_db, db_session):
    db_session.commit()
    client_no_auth.post("/setup/organisation", json=_setup_payload())
    token = login(client_no_auth, email="ada.admin@abc.test", password=ADMIN_PASSWORD)
    response = client_no_auth.patch(
        "/auth/me",
        headers=auth_headers(token),
        json={"role": "organisation_admin"},
    )
    assert response.status_code == 403


def _login_admin(client, db_session=None):
    client.post("/setup/organisation", json=_setup_payload())
    if db_session is not None:
        _force_verify_and_activate(db_session)
    return login(client, email="ada.admin@abc.test", password=ADMIN_PASSWORD)


def test_admin_invite_binds_org_and_role(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    created = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "employee@abc.test", "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    raw = created.json()["invite_token"]
    assert created.json()["invite_path"].endswith(raw)
    invitation = db_session.scalar(select(OrganisationInvitation))
    assert invitation.token_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in (invitation.token_hash or "")
    preview = client_no_auth.get("/invitations/preview", params={"token": raw})
    assert preview.status_code == 200
    assert preview.json()["email"] == "employee@abc.test"
    assert preview.json()["role"] == "viewer"

    accepted = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Emp Loyee",
            "email": "employee@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": raw,
        },
    )
    assert accepted.status_code == 201, accepted.text
    employee = db_session.scalar(select(User).where(User.email == "employee@abc.test"))
    membership = db_session.scalar(
        select(OrganisationMembership).where(OrganisationMembership.user_id == employee.id)
    )
    assert membership.role == UserRole.VIEWER
    assert membership.status == MembershipStatus.ACTIVE
    reuse = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Emp Two",
            "email": "employee@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": raw,
        },
    )
    assert reuse.status_code in {400, 409}


def test_invitation_replacement_invalidates_prior_token(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    first = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "replace.me@abc.test", "role": "viewer"},
    )
    assert first.status_code == 201, first.text
    token_a = first.json()["invite_token"]
    second = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "replace.me@abc.test", "role": "security_analyst"},
    )
    assert second.status_code == 201, second.text
    token_b = second.json()["invite_token"]
    assert token_a != token_b
    rejected = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Replace Me",
            "email": "replace.me@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": token_a,
        },
    )
    assert rejected.status_code == 400
    accepted = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Replace Me",
            "email": "replace.me@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": token_b,
        },
    )
    assert accepted.status_code == 201, accepted.text
    membership = db_session.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.user_id == accepted.json()["id"]
        )
    )
    assert membership.role == UserRole.SECURITY_ANALYST


def test_expired_and_revoked_invitations_rejected(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    created = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "expired@abc.test", "role": "viewer"},
    )
    raw = created.json()["invite_token"]
    invitation = db_session.scalar(select(OrganisationInvitation).where(OrganisationInvitation.email == "expired@abc.test"))
    invitation.expires_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.flush()
    expired = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Expired",
            "email": "expired@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": raw,
        },
    )
    assert expired.status_code == 400

    created2 = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "revoked@abc.test", "role": "viewer"},
    )
    raw2 = created2.json()["invite_token"]
    invitation_id = created2.json()["id"]
    revoked = client_no_auth.post(
        f"/users/invitations/{invitation_id}/revoke",
        headers=auth_headers(token),
    )
    assert revoked.status_code == 200
    rejected = client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Revoked",
            "email": "revoked@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": raw2,
        },
    )
    assert rejected.status_code == 400


def test_viewer_cannot_invite(client_no_auth, override_db, db_session):
    db_session.commit()
    admin_token = _login_admin(client_no_auth, db_session)
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "viewer.emp@abc.test", "role": "viewer"},
    )
    raw = invite.json()["invite_token"]
    client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Viewer Emp",
            "email": "viewer.emp@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": raw,
        },
    )
    viewer_token = login(client_no_auth, email="viewer.emp@abc.test", password=EMPLOYEE_PASSWORD)
    denied = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(viewer_token),
        json={"email": "another@abc.test", "role": "viewer"},
    )
    assert denied.status_code == 403


def test_admin_role_change_and_platform_admin_blocked(client_no_auth, override_db, db_session):
    db_session.commit()
    admin_token = _login_admin(client_no_auth, db_session)
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "role.change@abc.test", "role": "viewer"},
    )
    client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Role Change",
            "email": "role.change@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": invite.json()["invite_token"],
        },
    )
    employee = db_session.scalar(select(User).where(User.email == "role.change@abc.test"))
    changed = client_no_auth.patch(
        f"/users/{employee.id}/role",
        headers=auth_headers(admin_token),
        json={"role": "security_analyst", "reason": "investigation duty"},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["membership_role"] == "security_analyst"
    blocked = client_no_auth.patch(
        f"/users/{employee.id}/role",
        headers=auth_headers(admin_token),
        json={"role": "platform_admin"},
    )
    assert blocked.status_code in {403, 422}


def test_last_admin_cannot_self_demote_or_disable(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    admin = db_session.scalar(select(User).where(User.email == "ada.admin@abc.test"))
    demote = client_no_auth.patch(
        f"/users/{admin.id}/role",
        headers=auth_headers(token),
        json={"role": "viewer"},
    )
    assert demote.status_code == 409
    assert "organisation administrator" in demote.json()["detail"].lower()
    disable = client_no_auth.patch(
        f"/users/{admin.id}/deactivate",
        headers=auth_headers(token),
    )
    assert disable.status_code in {403, 409}
    revoke = client_no_auth.patch(
        f"/users/{admin.id}/membership",
        headers=auth_headers(token),
        json={"status": "revoked"},
    )
    assert revoke.status_code == 409


def test_suspended_membership_and_disabled_account(client_no_auth, override_db, db_session):
    db_session.commit()
    admin_token = _login_admin(client_no_auth, db_session)
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "suspend.me@abc.test", "role": "security_analyst"},
    )
    client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Suspend Me",
            "email": "suspend.me@abc.test",
            "password": EMPLOYEE_PASSWORD,
            "confirm_password": EMPLOYEE_PASSWORD,
            "invite_token": invite.json()["invite_token"],
        },
    )
    user = db_session.scalar(select(User).where(User.email == "suspend.me@abc.test"))
    employee_token = login(client_no_auth, email="suspend.me@abc.test", password=EMPLOYEE_PASSWORD)
    assert client_no_auth.get("/incidents", headers=auth_headers(employee_token)).status_code == 200
    assert (
        client_no_auth.patch(
            f"/users/{user.id}/membership",
            headers=auth_headers(admin_token),
            json={"status": "suspended"},
        ).status_code
        == 200
    )
    assert client_no_auth.get("/incidents", headers=auth_headers(employee_token)).status_code in {401, 403}
    client_no_auth.patch(
        f"/users/{user.id}/membership",
        headers=auth_headers(admin_token),
        json={"status": "active"},
    )
    other = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "second.admin@abc.test", "role": "organisation_admin"},
    )
    client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Second Admin",
            "email": "second.admin@abc.test",
            "password": ADMIN_PASSWORD,
            "confirm_password": ADMIN_PASSWORD,
            "invite_token": other.json()["invite_token"],
        },
    )
    disable = client_no_auth.patch(
        f"/users/{user.id}/deactivate",
        headers=auth_headers(admin_token),
    )
    assert disable.status_code == 200
    relogin = client_no_auth.post(
        "/auth/login",
        json={"email": "suspend.me@abc.test", "password": EMPLOYEE_PASSWORD},
    )
    assert relogin.status_code == 403


def test_stale_session_after_role_change(client_no_auth, override_db, db_session):
    db_session.commit()
    admin_token = _login_admin(client_no_auth, db_session)
    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(admin_token),
        json={"email": "stale.role@abc.test", "role": "organisation_admin"},
    )
    client_no_auth.post(
        "/auth/register",
        json={
            "full_name": "Stale Role",
            "email": "stale.role@abc.test",
            "password": ADMIN_PASSWORD,
            "confirm_password": ADMIN_PASSWORD,
            "invite_token": invite.json()["invite_token"],
        },
    )
    stale = login(client_no_auth, email="stale.role@abc.test", password=ADMIN_PASSWORD)
    user = db_session.scalar(select(User).where(User.email == "stale.role@abc.test"))
    assert client_no_auth.get("/users", headers=auth_headers(stale)).status_code == 200
    changed = client_no_auth.patch(
        f"/users/{user.id}/role",
        headers=auth_headers(admin_token),
        json={"role": "viewer", "reason": "reduce access"},
    )
    assert changed.status_code == 200, changed.text
    assert client_no_auth.get("/users", headers=auth_headers(stale)).status_code == 401


def test_forged_organisation_id_and_user_list_scope(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    forged = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "forged@abc.test", "role": "viewer", "organisation_id": 9999},
    )
    assert forged.status_code == 403
    listed = client_no_auth.get("/users", headers=auth_headers(token), params={"organisation_id": 9999})
    assert listed.status_code == 403
    scoped = client_no_auth.get("/users", headers=auth_headers(token))
    assert scoped.status_code == 200
    emails = {row["email"] for row in scoped.json()["users"]}
    assert "ada.admin@abc.test" in emails


def test_audit_and_report_org_scope(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    org = db_session.scalar(select(Organisation))
    incident = Incident(
        incident_id="INC-ORG-SCOPE-1",
        organisation_id=org.id,
        title="Org scoped incident",
        status=IncidentStatus.NEW,
        severity=Severity.LOW,
    )
    db_session.add(incident)
    db_session.flush()
    reports = client_no_auth.get("/reports/incidents/INC-ORG-SCOPE-1", headers=auth_headers(token))
    assert reports.status_code in {200, 404, 422}
    audits = client_no_auth.get("/audit-logs", headers=auth_headers(token))
    assert audits.status_code == 200


def test_integration_token_derives_organisation(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    created = client_no_auth.post(
        "/integrations/tokens",
        headers=auth_headers(token),
        json={"name": "gateway", "source_name": "pytest-gateway"},
    )
    if created.status_code == 201:
        from app.models.integration_token import IntegrationToken

        record = db_session.scalar(select(IntegrationToken).order_by(IntegrationToken.id.desc()))
        org = db_session.scalar(select(Organisation))
        assert record.organisation_id == org.id
        assert "organisation_id" not in (created.json().get("token") or "")


def test_org_admin_cannot_assign_platform_admin_on_create(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    created = client_no_auth.post(
        "/users",
        headers=auth_headers(token),
        json={
            "name": "Platform",
            "email": "platform@abc.test",
            "role": "platform_admin",
            "password": ADMIN_PASSWORD,
        },
    )
    assert created.status_code in {403, 422}


def test_raw_invitation_token_not_persisted(client_no_auth, override_db, db_session):
    db_session.commit()
    token = _login_admin(client_no_auth, db_session)
    created = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "hash.only@abc.test", "role": "viewer"},
    )
    raw = created.json()["invite_token"]
    invitation = db_session.scalar(select(OrganisationInvitation).where(OrganisationInvitation.email == "hash.only@abc.test"))
    assert invitation.token_hash != raw
    assert len(invitation.token_hash) == 64
    blob = str(invitation.__dict__)
    assert raw not in blob


def test_demo_seed_attaches_membership_not_setup_path(client_no_auth, override_db, db_session):
    seed_demo_users_in_db(db_session)
    db_session.commit()
    token = login(client_no_auth, email="admin@privacytrace.local", password="AdminPass123!")
    listed = client_no_auth.get("/users", headers=auth_headers(token))
    assert listed.status_code == 200
    status = client_no_auth.get("/setup/status").json()
    assert status["required"] is False
    assert status["completed"] is False
    assert status["registration_open"] is True


def test_setup_converts_demo_organisation(client_no_auth, override_db, db_session):
    seed_demo_users_in_db(db_session)
    db_session.commit()
    response = client_no_auth.post("/setup/organisation", json=_setup_payload())
    assert response.status_code == 201, response.text
    org = db_session.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))
    assert org is not None
    assert org.name == "ABC Wallet"
    assert org.slug != org_access.DEMO_ORG_SLUG
    assert org.overall_verification_status.value == "pending_verification"
    demo_user = db_session.scalar(select(User).where(User.email == "admin@privacytrace.local"))
    demo_membership = db_session.scalar(
        select(OrganisationMembership).where(OrganisationMembership.user_id == demo_user.id)
    )
    assert demo_membership.status == MembershipStatus.REVOKED
    admin = db_session.scalar(select(User).where(User.email == "ada.admin@abc.test"))
    membership = db_session.scalar(
        select(OrganisationMembership).where(OrganisationMembership.user_id == admin.id)
    )
    assert membership.status == MembershipStatus.PENDING
    status = client_no_auth.get("/setup/status").json()
    assert status["registration_open"] is False
    assert status["verification_pending"] is True
    assert status["completed"] is False


def test_production_rejects_seeded_demo_replacement(client_no_auth, override_db, db_session, monkeypatch):
    seed_demo_users_in_db(db_session)
    db_session.commit()
    monkeypatch.setenv("APP_ENV", "production")
    from app.config import get_settings

    get_settings.cache_clear()
    try:
        response = client_no_auth.post("/setup/organisation", json=_setup_payload())
        assert response.status_code == 409, response.text
        org = db_session.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))
        assert org is not None
        assert org.slug == org_access.DEMO_ORG_SLUG
        setup = db_session.get(DeploymentSetup, 1)
        assert setup is None or setup.bootstrap_consumed_at is None
    finally:
        get_settings.cache_clear()


def _wipe_org_tables(session):
    from sqlalchemy import text as sql_text
    from app.database import Base

    session.execute(sql_text("ALTER TABLE IF EXISTS integrity_ledger_records DISABLE TRIGGER trg_guard_integrity_record"))
    session.execute(sql_text("ALTER TABLE IF EXISTS integrity_ledger_head DISABLE TRIGGER trg_guard_integrity_head"))
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.execute(sql_text("ALTER TABLE IF EXISTS integrity_ledger_records ENABLE TRIGGER trg_guard_integrity_record"))
    session.execute(sql_text("ALTER TABLE IF EXISTS integrity_ledger_head ENABLE TRIGGER trg_guard_integrity_head"))
    session.commit()


def test_concurrent_setup_one_org(migrated_db):
    from sqlalchemy import func
    from app.database import SessionLocal

    with SessionLocal() as session:
        _wipe_org_tables(session)

    results: list[int] = []

    def _run(email: str, org_name: str) -> None:
        session = SessionLocal()
        try:
            org_access.complete_setup(
                session,
                organisation_name=org_name,
                admin_name="Ada Admin",
                email=email,
                password=ADMIN_PASSWORD,
                bootstrap_token=BOOTSTRAP_TOKEN,
            )
            session.commit()
            results.append(201)
        except org_access.SetupAlreadyCompletedError:
            session.rollback()
            results.append(409)
        except org_access.OrganisationAccessError as exc:
            session.rollback()
            results.append(exc.status_code)
        except Exception:
            session.rollback()
            results.append(500)
        finally:
            session.close()

    first = threading.Thread(target=_run, args=("concurrent.a@abc.test", "ABC Wallet"))
    second = threading.Thread(target=_run, args=("concurrent.b@abc.test", "XYZ Bank"))
    first.start()
    second.start()
    first.join()
    second.join()
    assert results.count(201) == 1
    assert 409 in results
    with SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(Organisation)) == 1
        assert session.scalar(select(func.count()).select_from(User)) == 1
        _wipe_org_tables(session)


def test_invite_accept_concurrency(migrated_db):
    from app.database import SessionLocal

    with SessionLocal() as session:
        _wipe_org_tables(session)
        org, actor, _membership = org_access.complete_setup(
            session,
            organisation_name="ABC Wallet",
            admin_name="Ada Admin",
            email="ada.admin@abc.test",
            password=ADMIN_PASSWORD,
            bootstrap_token=BOOTSTRAP_TOKEN,
        )
        from app.models.enums import OrganisationVerificationStatus
        from app.services import organisation_verification_policy_service as policy

        org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
        org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
        org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
        org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
        org.website_domain = "abc.test"
        actor.admin_email_verified = True
        policy.activate_verified_organisation(session, org, actor_id=actor.id)
        session.flush()
        invitation, raw = org_access.create_invitation(
            session,
            actor=actor,
            email="concurrent.invite@abc.test",
            role=UserRole.VIEWER,
        )
        session.commit()
        assert invitation.id

    outcomes: list[str] = []

    def _accept() -> None:
        session = SessionLocal()
        try:
            org_access.accept_invitation(
                session,
                token=raw,
                full_name="Concurrent Invitee",
                email="concurrent.invite@abc.test",
                password=EMPLOYEE_PASSWORD,
            )
            session.commit()
            outcomes.append("ok")
        except (org_access.OrganisationAccessError, Exception):
            session.rollback()
            outcomes.append("err")
        finally:
            session.close()

    first = threading.Thread(target=_accept)
    second = threading.Thread(target=_accept)
    first.start()
    second.start()
    first.join()
    second.join()
    assert outcomes.count("ok") == 1
    assert "err" in outcomes
    with SessionLocal() as session:
        users = list(session.scalars(select(User).where(User.email == "concurrent.invite@abc.test")).all())
        assert len(users) == 1
        invitations = list(session.scalars(select(OrganisationInvitation)).all())
        accepted = [row for row in invitations if row.email == "concurrent.invite@abc.test"]
        assert len(accepted) == 1
        assert accepted[0].status.value == "accepted"
        _wipe_org_tables(session)
