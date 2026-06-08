"""Create the deployment Platform Operator (platform_admin) via local bootstrap.

Usage (from backend/):
  set PRIVACYTRACE_BOOTSTRAP_TOKEN=...
  python -m app.db.bootstrap_platform_operator --email op@example.com --name "Platform Operator" --password '...'

Never available via /signup or organisation invites.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys

from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models.enums import UserRole
from app.models.user import User
from app.services import password_service, user_service


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bootstrap_platform_operator(
    *,
    email: str,
    name: str,
    password: str,
    bootstrap_token: str,
) -> User:
    settings = get_settings()
    expected = (settings.privacytrace_bootstrap_token or "").strip()
    provided = (bootstrap_token or "").strip()
    if not expected or not provided:
        raise RuntimeError("PRIVACYTRACE_BOOTSTRAP_TOKEN is required")
    if not secrets.compare_digest(_hash(provided), _hash(expected)):
        raise RuntimeError("Invalid bootstrap credential")

    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.role == UserRole.PLATFORM_ADMIN).limit(1))
        if existing is not None:
            raise RuntimeError("A Platform Operator already exists")
        user = user_service.create_user(
            db,
            name=name.strip(),
            email=email.strip().lower(),
            role=UserRole.PLATFORM_ADMIN,
            password=password,
        )
        user.admin_email_verified = True
        db.commit()
        db.refresh(user)
        return user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap Platform Operator")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", default="Platform Operator")
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--bootstrap-token",
        default="",
        help="Defaults to PRIVACYTRACE_BOOTSTRAP_TOKEN env/settings",
    )
    args = parser.parse_args(argv)
    token = args.bootstrap_token or get_settings().privacytrace_bootstrap_token
    try:
        user = bootstrap_platform_operator(
            email=args.email,
            name=args.name,
            password=args.password,
            bootstrap_token=token,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Platform Operator created id={user.id} email={user.email}")
    print("This account is not an Organisation Admin and cannot be invited via Users.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
