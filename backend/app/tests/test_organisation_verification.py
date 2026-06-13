"""Organisation legal/domain/email verification gates (mocked externals)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.enums import MembershipStatus, OrganisationVerificationStatus, UserRole
from app.models.organisation import Organisation, OrganisationDomainChallenge, OrganisationMembership
from app.models.user import User
from app.services import (
    company_registry_verification_service as registry_service,
    organisation_access_service as org_access,
    organisation_domain_verification_service as domain_service,
    organisation_email_verification_service as email_service,
    organisation_manual_review_service as manual_service,
    organisation_verification_policy_service as policy,
    pan_verification_service as pan_service,
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


def _register(client, **overrides):
    payload = {
        "organisation_name": "ABC Wallet",
        "administrator_full_name": "Ada Admin",
        "email": "ada.admin@abcwallet.test",
        "password": ADMIN_PASSWORD,
        "confirm_password": ADMIN_PASSWORD,
        "bootstrap_token": BOOTSTRAP_TOKEN,
        "legal_name": "ABC Wallet Pvt Ltd",
        "registration_number": "123456",
        "website_domain": "abcwallet.test",
    }
    payload.update(overrides)
    return client.post("/setup/organisation", json=payload)


def test_company_starts_pending(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    assert _register(client_no_auth).status_code == 201
    org = db_session.scalar(select(Organisation))
    assert org.overall_verification_status == OrganisationVerificationStatus.PENDING_VERIFICATION
    membership = db_session.scalar(select(OrganisationMembership))
    assert membership.status == MembershipStatus.PENDING


def test_name_alone_cannot_activate_admin(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    assert client_no_auth.get("/incidents", headers=auth_headers(token)).status_code == 403
    assert client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "x@abcwallet.test", "role": "viewer"},
    ).status_code == 403


def test_registry_match_and_mismatch(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    ok = client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(token),
        json={"legal_name": "ABC Wallet Pvt Ltd", "registration_number": "123456"},
    )
    assert ok.status_code == 200
    assert ok.json()["legal_verification_status"] == "verified"
    assert ok.json()["demo_banner"] == "Demo Organisation — Verification Simulated"
    # mismatch path on fresh org fields — re-set and mismatch
    org = db_session.scalar(select(Organisation))
    org.legal_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
    db_session.commit()
    bad = client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(token),
        json={"legal_name": "ABC Wallet Pvt Ltd", "registration_number": "123456X"},
    )
    assert bad.status_code == 200
    assert bad.json()["overall_verification_status"] == "manual_review"


def test_registry_unavailable_routes_manual(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    resp = client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(token),
        json={"legal_name": "ABC", "registration_number": "99U"},
    )
    assert resp.json()["overall_verification_status"] == "manual_review"


def test_pan_optional_and_required(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    monkeypatch.setenv("PAN_VERIFICATION_REQUIRED", "false")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    org = db_session.scalar(select(Organisation))
    org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
    assert policy.policy_requirements_met(org) is True

    monkeypatch.setenv("PAN_VERIFICATION_REQUIRED", "true")
    get_settings.cache_clear()
    assert policy.policy_requirements_met(org) is False
    org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
    assert policy.policy_requirements_met(org) is True
    get_settings.cache_clear()


def test_dns_challenge_and_verify(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    challenge = client_no_auth.post(
        "/setup/verification/domain/challenge",
        headers=auth_headers(token),
        json={"domain": "abcwallet.test"},
    )
    assert challenge.status_code == 200, challenge.text
    txt = challenge.json()["txt_record"]
    assert txt.startswith("privacytrace-verification=")
    token_secret = txt.split("=", 1)[1]

    def fake_lookup(_domain):
        return [txt]

    monkeypatch.setattr(domain_service, "_txt_lookup", fake_lookup)
    # inject via verify call path — monkeypatch module used by router
    import app.services.organisation_domain_verification_service as dmod

    monkeypatch.setattr(dmod, "_txt_lookup", fake_lookup)
    verified = client_no_auth.post("/setup/verification/domain/verify", headers=auth_headers(token))
    assert verified.status_code == 200, verified.text
    assert verified.json()["domain_verification_status"] == "verified"

    # incorrect TXT
    org = db_session.scalar(select(Organisation))
    org.domain_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
    db_session.commit()
    challenge2 = client_no_auth.post(
        "/setup/verification/domain/challenge",
        headers=auth_headers(token),
        json={"domain": "abcwallet.test"},
    )
    monkeypatch.setattr(dmod, "_txt_lookup", lambda _d: ["privacytrace-verification=wrong"])
    bad = client_no_auth.post("/setup/verification/domain/verify", headers=auth_headers(token))
    assert bad.status_code == 400

    # expired
    row = db_session.scalar(
        select(OrganisationDomainChallenge).order_by(OrganisationDomainChallenge.id.desc()).limit(1)
    )
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    row.status = __import__("app.models.enums", fromlist=["DomainChallengeStatus"]).DomainChallengeStatus.PENDING
    db_session.commit()
    monkeypatch.setattr(dmod, "_txt_lookup", lambda _d: [challenge2.json()["txt_record"]])
    expired = client_no_auth.post("/setup/verification/domain/verify", headers=auth_headers(token))
    assert expired.status_code == 400
    assert "expired" in expired.json()["detail"].lower()
    _ = token_secret


def test_demo_domain_verify_accepts_presented_txt(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    challenge = client_no_auth.post(
        "/setup/verification/domain/challenge",
        headers=auth_headers(token),
        json={"domain": "abcwallet.test"},
    )
    txt = challenge.json()["txt_record"]
    verified = client_no_auth.post(
        "/setup/verification/domain/verify",
        headers=auth_headers(token),
        json={"txt_record": txt},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["domain_verification_status"] == "verified"


def test_shared_email_domain_rejected(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    resp = client_no_auth.post(
        "/setup/verification/domain/challenge",
        headers=auth_headers(token),
        json={"domain": "gmail.com"},
    )
    assert resp.status_code == 400


def test_email_token_single_use_and_expiry(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth, website_domain=None)
    org = db_session.scalar(select(Organisation))
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    org.website_domain = "abcwallet.test"
    org.allow_external_admin_email = True
    db_session.commit()
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    issued = client_no_auth.post("/setup/verification/email/issue", headers=auth_headers(token))
    assert issued.status_code == 200
    raw = issued.json()["verify_token"]
    assert raw
    ok = client_no_auth.post(
        "/setup/verification/email/confirm",
        headers=auth_headers(token),
        json={"token": raw},
    )
    assert ok.status_code == 200
    assert ok.json()["admin_email_verification_status"] == "verified"
    reuse = client_no_auth.post(
        "/setup/verification/email/confirm",
        headers=auth_headers(token),
        json={"token": raw},
    )
    assert reuse.status_code == 400

    issued2 = client_no_auth.post("/setup/verification/email/issue", headers=auth_headers(token))
    raw2 = issued2.json()["verify_token"]
    from app.models.organisation import OrganisationEmailVerification

    row = db_session.scalar(
        select(OrganisationEmailVerification).order_by(OrganisationEmailVerification.id.desc()).limit(1)
    )
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    expired = client_no_auth.post(
        "/setup/verification/email/confirm",
        headers=auth_headers(token),
        json={"token": raw2},
    )
    assert expired.status_code == 400


def test_client_cannot_forge_verification_status(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    forged = client_no_auth.post(
        "/setup/organisation",
        headers=auth_headers(token),
        json={
            "organisation_name": "Hack",
            "administrator_full_name": "H",
            "email": "h@x.test",
            "password": ADMIN_PASSWORD,
            "confirm_password": ADMIN_PASSWORD,
            "overall_verification_status": "verified",
            "verified_by": 1,
        },
    )
    assert forged.status_code == 422


def test_full_activation_and_invite_gate(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    monkeypatch.setenv("PAN_VERIFICATION_REQUIRED", "false")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth, email="ada.admin@abcwallet.test")
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    assert client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "emp@abcwallet.test", "role": "viewer"},
    ).status_code == 403

    client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(token),
        json={"legal_name": "ABC Wallet Pvt Ltd", "registration_number": "123456"},
    )
    challenge = client_no_auth.post(
        "/setup/verification/domain/challenge",
        headers=auth_headers(token),
        json={"domain": "abcwallet.test"},
    )
    txt = challenge.json()["txt_record"]
    import app.services.organisation_domain_verification_service as dmod

    monkeypatch.setattr(dmod, "_txt_lookup", lambda _d: [txt])
    client_no_auth.post("/setup/verification/domain/verify", headers=auth_headers(token))
    issued = client_no_auth.post("/setup/verification/email/issue", headers=auth_headers(token))
    client_no_auth.post(
        "/setup/verification/email/confirm",
        headers=auth_headers(token),
        json={"token": issued.json()["verify_token"]},
    )
    status = client_no_auth.get("/setup/verification/status", headers=auth_headers(token))
    assert status.json()["overall_verification_status"] == "verified"
    membership = db_session.scalar(select(OrganisationMembership))
    db_session.refresh(membership)
    assert membership.status == MembershipStatus.ACTIVE

    invite = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "emp@abcwallet.test", "role": "viewer"},
    )
    assert invite.status_code == 201, invite.text


def test_demo_convert_activation_promotes_new_admin_not_revoked_demo(
    client_no_auth, override_db, db_session, monkeypatch
):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    monkeypatch.setenv("PAN_VERIFICATION_REQUIRED", "false")
    from app.config import get_settings
    from app.tests.auth_test_utils import seed_demo_users_in_db

    get_settings.cache_clear()
    seed_demo_users_in_db(db_session)
    db_session.commit()
    assert _register(client_no_auth).status_code == 201
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    client_no_auth.post(
        "/setup/verification/legal",
        headers=auth_headers(token),
        json={"legal_name": "ABC Wallet Pvt Ltd", "registration_number": "123456"},
    )
    challenge = client_no_auth.post(
        "/setup/verification/domain/challenge",
        headers=auth_headers(token),
        json={"domain": "abcwallet.test"},
    )
    txt = challenge.json()["txt_record"]
    verified = client_no_auth.post(
        "/setup/verification/domain/verify",
        headers=auth_headers(token),
        json={"txt_record": txt},
    )
    assert verified.status_code == 200, verified.text
    issued = client_no_auth.post("/setup/verification/email/issue", headers=auth_headers(token))
    confirm = client_no_auth.post(
        "/setup/verification/email/confirm",
        headers=auth_headers(token),
        json={"token": issued.json()["verify_token"]},
    )
    assert confirm.status_code == 200, confirm.text
    assert confirm.json()["overall_verification_status"] == "verified"
    ada = db_session.scalar(select(User).where(User.email == "ada.admin@abcwallet.test"))
    ada_membership = db_session.scalar(
        select(OrganisationMembership).where(OrganisationMembership.user_id == ada.id)
    )
    db_session.refresh(ada_membership)
    assert ada_membership.status == MembershipStatus.ACTIVE
    demo = db_session.scalar(select(User).where(User.email == "admin@privacytrace.local"))
    demo_membership = db_session.scalar(
        select(OrganisationMembership).where(OrganisationMembership.user_id == demo.id)
    )
    db_session.refresh(demo_membership)
    assert demo_membership.status == MembershipStatus.REVOKED
    assert client_no_auth.get("/incidents", headers=auth_headers(token)).status_code == 200


def test_manual_review_requires_platform_admin(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    req = client_no_auth.post(
        "/setup/verification/manual-review",
        headers=auth_headers(token),
        json={"reason": "no corporate domain"},
    )
    assert req.status_code == 200
    from app.models.organisation import OrganisationManualReview
    from app.services import user_service

    review = db_session.scalar(select(OrganisationManualReview))
    denied = client_no_auth.post(
        f"/setup/verification/manual-review/{review.id}/decide",
        headers=auth_headers(token),
        json={"decision": "approve", "notes_safe": "looks fine"},
    )
    assert denied.status_code == 403

    platform = user_service.create_user(
        db_session,
        name="Platform",
        email="platform@privacytrace.test",
        role=UserRole.PLATFORM_ADMIN,
        password=ADMIN_PASSWORD,
    )
    db_session.commit()
    ptoken = login(client_no_auth, email="platform@privacytrace.test", password=ADMIN_PASSWORD)
    ok = client_no_auth.post(
        f"/setup/verification/manual-review/{review.id}/decide",
        headers=auth_headers(ptoken),
        json={"decision": "approve", "notes_safe": "OCR reference checked"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["overall_verification_status"] == "verified"
    _ = platform


def test_demo_cannot_masquerade_as_ocr(monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    result = registry_service.verify_company_registration(
        legal_name="Demo Co",
        registration_number="1",
    )
    assert result.verification_method == "DEMO_SIMULATED"
    assert result.source == "DEMO_SIMULATED"
    assert "OCR" not in result.verification_method


def test_platform_admin_escalation_still_blocked(client_no_auth, override_db, db_session, monkeypatch):
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "demo")
    from app.config import get_settings

    get_settings.cache_clear()
    db_session.commit()
    _register(client_no_auth)
    org = db_session.scalar(select(Organisation))
    org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
    user = db_session.scalar(select(User))
    user.admin_email_verified = True
    policy.activate_verified_organisation(db_session, org, actor_id=user.id)
    db_session.commit()
    token = login(client_no_auth, email="ada.admin@abcwallet.test", password=ADMIN_PASSWORD)
    resp = client_no_auth.post(
        "/users/invitations",
        headers=auth_headers(token),
        json={"email": "x@abcwallet.test", "role": "platform_admin"},
    )
    assert resp.status_code in (403, 422)
