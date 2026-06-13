"""Phase 11.6 â€” authentication and RBAC tests."""

import io
import pytest
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.models.root_cause_score import RootCauseScore
from app.models.user import User
from app.services import password_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db")


@pytest.fixture(autouse=True)
def override_db_session_for_auth_api(db_session):
    """Route API requests through the test transaction so seeded users are visible."""
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


def test_passwords_are_hashed(demo_users):
    admin = demo_users["admin"]["user"]
    assert admin.password_hash
    assert admin.password_hash != demo_users["admin"]["password"]
    assert password_service.verify_password(
        demo_users["admin"]["password"], admin.password_hash
    )


def test_plaintext_password_not_stored(demo_users, db_session):
    admin = db_session.get(User, demo_users["admin"]["user"].id)
    assert admin.password_hash is not None
    assert "AdminPass123!" not in (admin.password_hash or "")


def test_login_succeeds_with_valid_demo_user(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    assert token


def test_login_fails_with_wrong_password(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/login",
        json={"email": "admin@privacytrace.local", "password": "WrongPassword!"},
    )
    assert response.status_code == 401


def test_login_fails_for_inactive_user(client_no_auth_override, demo_users, db_session):
    user = demo_users["viewer"]["user"]
    user.is_active = False
    db_session.commit()
    response = client_no_auth_override.post(
        "/auth/login",
        json={"email": "viewer@privacytrace.local", "password": "ViewerPass123!"},
    )
    assert response.status_code == 403


def test_auth_me_returns_current_user(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )
    response = client_no_auth_override.get("/auth/me", headers=auth_headers(token))
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "analyst@privacytrace.local"
    assert body["role"] == "security_analyst"


def test_protected_endpoint_401_without_token(client_no_auth_override, db_session):
    db_session.commit()
    response = client_no_auth_override.get("/incidents")
    assert response.status_code == 401


def test_protected_endpoint_403_for_insufficient_role(
    client_no_auth_override, demo_users, db_session
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )
    response = client_no_auth_override.get("/audit-logs", headers=auth_headers(token))
    assert response.status_code == 403


def test_admin_can_list_users(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    response = client_no_auth_override.get("/users", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json()["total"] >= 5



def test_evidence_upload_ignores_client_uploaded_by(
    client_no_auth_override, demo_users, db_session
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    response = client_no_auth_override.post(
        "/evidence/upload",
        headers=auth_headers(token),
        data={"evidence_type": "api_log", "uploaded_by": "99999"},
        files={
            "file": (
                "spoof-check.log",
                io.BytesIO(b'{"timestamp":"2026-05-20T10:15:00Z","message":"safe"}'),
                "text/plain",
            )
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["evidence"]["uploaded_by"] == demo_users["admin"]["user"].id

def test_non_admin_cannot_list_users(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )
    response = client_no_auth_override.get("/users", headers=auth_headers(token))
    assert response.status_code == 403


def test_admin_can_create_user(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    response = client_no_auth_override.post(
        "/users",
        headers=auth_headers(token),
        json={
            "name": "New Analyst",
            "email": "new.analyst@privacytrace.local",
            "role": "security_analyst",
            "password": "NewAnalystPass123!",
        },
    )
    assert response.status_code == 201
    assert "password_hash" not in response.text


def test_admin_cannot_create_user_with_weak_password(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    response = client_no_auth_override.post(
        "/users",
        headers=auth_headers(token),
        json={
            "name": "Weak Password",
            "email": "weak.password@privacytrace.local",
            "role": "viewer",
            "password": "weakpass",
        },
    )
    assert response.status_code == 422
    assert "weakpass" not in response.text


def test_created_user_has_hashed_password(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    client_no_auth_override.post(
        "/users",
        headers=auth_headers(token),
        json={
            "name": "Hashed Check",
            "email": "hashed.check@privacytrace.local",
            "role": "viewer",
            "password": "HashedCheck123!",
        },
    )
    user = db_session.scalar(
        select(User).where(User.email == "hashed.check@privacytrace.local")
    )
    assert user is not None
    assert user.password_hash
    assert password_service.verify_password("HashedCheck123!", user.password_hash)


def test_password_hash_never_returned_in_api(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )
    response = client_no_auth_override.get("/users", headers=auth_headers(token))
    assert "password_hash" not in response.text


def test_security_analyst_can_submit_review(
    client_no_auth_override, demo_users, db_session, seeded_db
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )
    response = client_no_auth_override.post(
        "/incidents/INC-SEED-001/review",
        headers=auth_headers(token),
        json={"decision": "request_more_evidence", "comment": "Need retest evidence"},
    )
    assert response.status_code in (200, 422)


def test_viewer_cannot_submit_review(client_no_auth_override, demo_users, db_session, seeded_db):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )
    response = client_no_auth_override.post(
        "/incidents/INC-SEED-001/review",
        headers=auth_headers(token),
        json={"decision": "approved", "comment": "Should not be allowed"},
    )
    assert response.status_code == 403


def test_auditor_can_view_audit_logs(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="auditor@privacytrace.local",
        password="AuditorPass123!",
    )
    response = client_no_auth_override.get("/audit-logs", headers=auth_headers(token))
    assert response.status_code == 200


def test_developer_cannot_view_audit_logs(client_no_auth_override, demo_users, db_session):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="developer@privacytrace.local",
        password="DeveloperPass123!",
    )
    response = client_no_auth_override.get("/audit-logs", headers=auth_headers(token))
    assert response.status_code == 403


def test_fix_verification_requires_allowed_role(
    client_no_auth_override, demo_users, db_session, seeded_db
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )
    response = client_no_auth_override.post(
        "/incidents/INC-SEED-001/verify-fix",
        headers=auth_headers(token),
        json={"retest_evidence_ids": ["EVD-FIXED-001"]},
    )
    assert response.status_code == 403


def test_audit_log_records_actor_id_for_review(
    client_no_auth_override, demo_users, db_session, seeded_db
):
    db_session.add(
        RootCauseScore(
            root_cause_id="RCA-AUTH-TEST-001",
            incident_id="INC-SEED-001",
            cause_name="test_cause",
            likely_root_cause="test_cause",
            confidence=0.75,
            confidence_band="medium",
            rank=1,
            human_review_required=True,
        )
    )
    db_session.flush()
    analyst = demo_users["security_analyst"]["user"]
    token = login(
        client_no_auth_override,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )
    response = client_no_auth_override.post(
        "/incidents/INC-SEED-001/review",
        headers=auth_headers(token),
        json={"decision": "request_more_evidence", "comment": "Recorded for audit test"},
    )
    assert response.status_code == 200, response.text
    log = db_session.scalar(
        select(AuditLog)
        .where(AuditLog.action == "review_submitted")
        .order_by(AuditLog.id.desc())
    )
    assert log is not None
    assert log.actor_id == analyst.id


def test_audit_log_does_not_store_password_or_token(
    client_no_auth_override, demo_users, db_session
):
    db_session.commit()
    client_no_auth_override.post(
        "/auth/login",
        json={"email": "admin@privacytrace.local", "password": "AdminPass123!"},
    )
    logs = db_session.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(5)).all()
    for log in logs:
        blob = str(log.details or {})
        assert "AdminPass123!" not in blob
        assert "eyJ" not in blob


def test_permission_denied_is_audited_safely(
    client_no_auth_override, demo_users, db_session
):
    db_session.commit()
    token = login(
        client_no_auth_override,
        email="developer@privacytrace.local",
        password="DeveloperPass123!",
    )
    client_no_auth_override.get("/audit-logs", headers=auth_headers(token))
    log = db_session.scalar(
        select(AuditLog)
        .where(AuditLog.action == "permission_denied")
        .order_by(AuditLog.id.desc())
    )
    assert log is not None
    assert log.actor_id == demo_users["developer"]["user"].id
    assert "password" not in str(log.details or {}).lower()
