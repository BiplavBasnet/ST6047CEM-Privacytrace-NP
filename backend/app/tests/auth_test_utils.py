"""Helpers for Phase 11.6 authentication tests."""

from fastapi.testclient import TestClient

from app.db.seed_auth_users import DEMO_USERS
from app.services import password_service


def login(client: TestClient, *, email: str, password: str) -> str:
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def seed_demo_users_in_db(db_session) -> dict[str, dict]:
    from app.models.user import User

    users: dict[str, dict] = {}
    for spec in DEMO_USERS:
        user = User(
            name=spec["name"],
            email=spec["email"],
            role=spec["role"],
            password_hash=password_service.hash_password(spec["password"]),
            is_active=True,
        )
        db_session.add(user)
        db_session.flush()
        users[spec["role"].value] = {
            "user": user,
            "email": spec["email"],
            "password": spec["password"],
        }
    from app.services import organisation_access_service as org_access

    org_access.attach_demo_memberships(db_session, [item["user"] for item in users.values()])
    return users
