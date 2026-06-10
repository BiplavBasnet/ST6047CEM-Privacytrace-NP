"""First-admin work-email verification tokens (hashed, single-use, expiring)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import OrganisationVerificationStatus
from app.models.organisation import Organisation, OrganisationEmailVerification
from app.models.user import User


class EmailVerificationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def hash_email_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def email_domain(email: str) -> str:
    return (email or "").strip().lower().rsplit("@", 1)[-1]


def issue_email_verification(
    db: Session,
    org: Organisation,
    user: User,
) -> tuple[OrganisationEmailVerification, str]:
    settings = get_settings()
    now = datetime.now(UTC)
    # Invalidate prior unused tokens for this user.
    prior = db.scalars(
        select(OrganisationEmailVerification).where(
            OrganisationEmailVerification.user_id == user.id,
            OrganisationEmailVerification.consumed_at.is_(None),
        )
    ).all()
    for row in prior:
        row.consumed_at = now
    token = secrets.token_urlsafe(32)
    row = OrganisationEmailVerification(
        organisation_id=org.id,
        user_id=user.id,
        email=user.email.strip().lower(),
        token_hash=hash_email_token(token),
        expires_at=now + timedelta(minutes=max(5, int(settings.email_verification_ttl_minutes))),
        attempt_count=0,
    )
    db.add(row)
    org.admin_email_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
    db.flush()
    return row, token


def invalidate_for_email_change(db: Session, user: User) -> None:
    """Unused email tokens and org email verification cannot survive an identity change."""
    now = datetime.now(UTC)
    prior = db.scalars(
        select(OrganisationEmailVerification).where(
            OrganisationEmailVerification.user_id == user.id,
            OrganisationEmailVerification.consumed_at.is_(None),
        )
    ).all()
    for row in prior:
        row.consumed_at = now
    user.admin_email_verified = False
    from app.services import organisation_access_service as org_access
    from app.services import organisation_verification_policy_service as policy

    membership = org_access.get_pending_membership(db, user) or org_access.get_active_membership(
        db, user
    )
    if membership is None or not org_access.is_org_admin_role(membership.role):
        return
    org = membership.organisation or db.get(Organisation, membership.organisation_id)
    if org is None:
        return
    org.admin_email_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
    policy.recompute_and_maybe_activate(db, org, actor_id=user.id)


def consume_email_verification(
    db: Session,
    *,
    token: str,
    user: User | None = None,
) -> OrganisationEmailVerification:
    settings = get_settings()
    token_hash = hash_email_token(token)
    stmt = (
        select(OrganisationEmailVerification)
        .where(OrganisationEmailVerification.token_hash == token_hash)
        .with_for_update()
        .limit(1)
    )
    row = db.scalar(stmt)
    if row is None:
        raise EmailVerificationError("Invalid email verification token", status_code=400)
    if user is not None and row.user_id != user.id:
        raise EmailVerificationError("Email verification token does not match user", status_code=403)
    max_attempts = max(1, int(settings.email_verification_max_attempts))
    row.attempt_count = int(row.attempt_count or 0) + 1
    if int(row.attempt_count) > max_attempts:
        raise EmailVerificationError("Email verification rate limit exceeded", status_code=429)
    now = datetime.now(UTC)
    if row.consumed_at is not None:
        raise EmailVerificationError("Email verification token already used", status_code=400)
    if row.expires_at <= now:
        raise EmailVerificationError("Email verification token expired", status_code=400)

    org = db.get(Organisation, row.organisation_id)
    target = db.get(User, row.user_id)
    if org is None or target is None:
        raise EmailVerificationError("Verification target missing", status_code=404)

    if (
        org.domain_verification_status == OrganisationVerificationStatus.VERIFIED
        and org.website_domain
        and not org.allow_external_admin_email
        and email_domain(target.email) != org.website_domain.lower()
    ):
        raise EmailVerificationError(
            "Administrator email domain must match the verified company domain "
            "(or request a documented external-admin exception via manual review)",
            status_code=400,
        )

    row.consumed_at = now
    target.admin_email_verified = True
    org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
    db.flush()
    return row
