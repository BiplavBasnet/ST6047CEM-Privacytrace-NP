"""Password reset tokens (hashed, single-use, expiring)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.organisation import PasswordResetToken
from app.models.user import User
from app.services import email_delivery_service, organisation_access_service as org_access, password_service


class PasswordResetError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def request_password_reset(db: Session, email: str) -> str | None:
    """Always succeed outwardly (no account enumeration). Returns demo token only when allowed."""
    settings = get_settings()
    normalised = (email or "").strip().lower()
    user = db.scalar(select(User).where(User.email == normalised).limit(1))
    if user is None or not user.is_active:
        return None
    now = datetime.now(UTC)
    prior = db.scalars(
        select(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
        )
    ).all()
    for row in prior:
        row.consumed_at = now
    token = secrets.token_urlsafe(32)
    row = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_reset_token(token),
        expires_at=now + timedelta(minutes=max(5, int(settings.password_reset_ttl_minutes))),
        attempt_count=0,
    )
    db.add(row)
    db.flush()
    link = email_delivery_service.build_frontend_link(f"/reset-password?token={token}")
    body = (
        "PrivacyTrace-NP password reset\n\n"
        f"Use this one-time link within the expiry window:\n{link}\n\n"
        "If you did not request this, ignore this message."
    )
    if email_delivery_service.smtp_configured():
        try:
            email_delivery_service.send_email(
                to_address=user.email,
                subject="PrivacyTrace-NP password reset",
                body_text=body,
            )
        except email_delivery_service.EmailDeliveryError:
            pass
        return None
    if email_delivery_service.demo_token_exposure_allowed():
        return token
    return None


def consume_password_reset(db: Session, *, token: str, new_password: str) -> User:
    settings = get_settings()
    token_hash = hash_reset_token(token)
    row = db.scalar(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_hash)
        .with_for_update()
        .limit(1)
    )
    if row is None:
        raise PasswordResetError("Invalid or expired reset token")
    row.attempt_count = int(row.attempt_count or 0) + 1
    if int(row.attempt_count) > max(1, int(settings.password_reset_max_attempts)):
        raise PasswordResetError("Reset rate limit exceeded", status_code=429)
    now = datetime.now(UTC)
    if row.consumed_at is not None or row.expires_at <= now:
        raise PasswordResetError("Invalid or expired reset token")
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise PasswordResetError("Invalid or expired reset token")

    user.password_hash = password_service.hash_password(new_password)
    user.password_hash_algorithm = password_service.PREFERRED_ALGORITHM
    user.password_updated_at = now
    row.consumed_at = now
    org_access.bump_token_version(user)
    db.flush()
    return user
