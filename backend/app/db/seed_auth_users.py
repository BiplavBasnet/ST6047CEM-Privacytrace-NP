"""Seed demo users with hashed passwords for Phase 11.6 authentication."""

from datetime import UTC, datetime

from sqlalchemy import select

from app.config import synthetic_demo_actions_allowed
from app.database import SessionLocal
from app.models.enums import UserRole
from app.models.user import User
from app.services import organisation_access_service as org_access, password_service

DEMO_USERS = (
    {
        "name": "Admin User",
        "email": "admin@privacytrace.local",
        "password": "AdminPass123!",
        "role": UserRole.ADMIN,
    },
    {
        "name": "Security Analyst",
        "email": "analyst@privacytrace.local",
        "password": "AnalystPass123!",
        "role": UserRole.SECURITY_ANALYST,
    },
    {
        "name": "Developer User",
        "email": "developer@privacytrace.local",
        "password": "DeveloperPass123!",
        "role": UserRole.DEVELOPER,
    },
    {
        "name": "Auditor User",
        "email": "auditor@privacytrace.local",
        "password": "AuditorPass123!",
        "role": UserRole.AUDITOR,
    },
    {
        "name": "Viewer User",
        "email": "viewer@privacytrace.local",
        "password": "ViewerPass123!",
        "role": UserRole.VIEWER,
    },
    {
        "name": "DevSecOps Engineer",
        "email": "devsecops@privacytrace.local",
        "password": "DevSecOpsPass123!",
        "role": UserRole.DEVSECOPS_ENGINEER,
    },
)


def seed_auth_users() -> None:
    if not synthetic_demo_actions_allowed():
        print("Demo auth seed skipped (not a development/test environment).")
        print("Company onboarding uses /setup — demo credentials are not company onboarding.")
        return
    db = SessionLocal()
    try:
        seeded: list[User] = []
        for spec in DEMO_USERS:
            existing = db.scalar(select(User).where(User.email == spec["email"]))
            password_hash = password_service.hash_password(spec["password"])
            now = datetime.now(UTC)
            if existing:
                existing.name = spec["name"]
                existing.role = spec["role"]
                existing.password_hash = password_hash
                existing.password_hash_algorithm = password_service.PREFERRED_ALGORITHM
                existing.password_updated_at = now
                existing.is_active = True
                seeded.append(existing)
            else:
                user = User(
                    name=spec["name"],
                    email=spec["email"],
                    role=spec["role"],
                    password_hash=password_hash,
                    password_hash_algorithm=password_service.PREFERRED_ALGORITHM,
                    password_updated_at=now,
                    is_active=True,
                )
                db.add(user)
                db.flush()
                seeded.append(user)
        org_access.attach_demo_memberships(db, seeded)
        db.commit()
        print("Auth users seeded (synthetic demo passwords — not for production).")
        print("Demo credentials are not company onboarding. Fresh deployments use /setup.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_auth_users()
