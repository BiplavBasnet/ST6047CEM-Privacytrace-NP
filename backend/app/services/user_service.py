"""User management for admin operations."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import UserRole
from app.models.user import User
from app.services import password_service


class UserNotFoundError(Exception):
    pass


class DuplicateEmailError(Exception):
    pass


def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


def list_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)).all())


def get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise UserNotFoundError(f"User {user_id} not found")
    return user


def create_user(
    db: Session,
    *,
    name: str,
    email: str,
    role: UserRole,
    password: str,
) -> User:
    normalised = normalise_email(email)
    if db.scalar(select(User).where(User.email == normalised)):
        raise DuplicateEmailError(f"Email already registered: {normalised}")
    now = datetime.now(UTC)
    user = User(
        name=name,
        email=normalised,
        role=role,
        password_hash=password_service.hash_password(password),
        password_hash_algorithm=password_service.PREFERRED_ALGORITHM,
        password_updated_at=now,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def update_user(
    db: Session,
    user_id: int,
    *,
    name: str | None = None,
    email: str | None = None,
    role: UserRole | None = None,
    is_active: bool | None = None,
    password: str | None = None,
) -> User:
    user = get_user(db, user_id)
    email_changed = False
    if email is not None and normalise_email(email) != user.email:
        normalised = normalise_email(email)
        if db.scalar(select(User).where(User.email == normalised)):
            raise DuplicateEmailError(f"Email already registered: {normalised}")
        user.email = normalised
        email_changed = True
    if name is not None:
        user.name = name
    if role is not None:
        user.role = role
    if is_active is not None:
        user.is_active = is_active
    if password is not None:
        user.password_hash = password_service.hash_password(password)
        user.password_hash_algorithm = password_service.PREFERRED_ALGORITHM
        user.password_updated_at = datetime.now(UTC)
    if email_changed or password is not None:
        from app.services import organisation_access_service as org_access

        org_access.bump_token_version(user)
    if email_changed:
        from app.services import organisation_email_verification_service as email_verify

        email_verify.invalidate_for_email_change(db, user)
    db.flush()
    return user


def deactivate_user(db: Session, user_id: int) -> User:
    return update_user(db, user_id, is_active=False)
