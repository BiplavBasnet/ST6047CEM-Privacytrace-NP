"""Revocable ingestion-only tokens for the Universal Integration Gateway."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.integration_token import IntegrationToken
from app.services import audit_service

TOKEN_PREFIX = "ptig_"


class InvalidIntegrationTokenError(ValueError):
    pass


class IntegrationTokenNotFoundError(ValueError):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(
    db: Session,
    *,
    name: str,
    source_name: str,
    created_by_user_id: int,
    actor_email: str,
    actor_role: str,
    organisation_id: int | None = None,
) -> tuple[IntegrationToken, str]:
    raw_token = f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    record = IntegrationToken(
        token_id=f"ITK-{uuid.uuid4().hex[:12].upper()}",
        name=name.strip(),
        source_name=source_name.strip(),
        token_hash=_hash_token(raw_token),
        token_prefix=f"{raw_token[:12]}...",
        created_by_user_id=created_by_user_id,
        organisation_id=organisation_id,
        is_active=True,
    )
    db.add(record)
    db.flush()
    audit_service.log_action(
        db,
        action="integration_token_created",
        actor_id=created_by_user_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="integration_token",
        target_id=record.token_id,
        details={"name": record.name, "source_name": record.source_name},
    )
    db.commit()
    db.refresh(record)
    return record, raw_token


def list_tokens(db: Session, organisation_id: int | None = None) -> list[IntegrationToken]:
    stmt = select(IntegrationToken).order_by(
        IntegrationToken.is_active.desc(),
        IntegrationToken.created_at.desc(),
    )
    if organisation_id is not None:
        stmt = stmt.where(
            (IntegrationToken.organisation_id == organisation_id)
            | (IntegrationToken.organisation_id.is_(None))
        )
    return list(db.scalars(stmt).all())


def authenticate_token(db: Session, raw_token: str) -> IntegrationToken:
    if not raw_token.startswith(TOKEN_PREFIX) or len(raw_token) < 30:
        raise InvalidIntegrationTokenError("Invalid integration token.")
    record = db.scalar(
        select(IntegrationToken).where(
            IntegrationToken.token_hash == _hash_token(raw_token)
        )
    )
    if not record or not record.is_active:
        raise InvalidIntegrationTokenError("Invalid or inactive integration token.")
    record.last_used_at = datetime.now(UTC)
    db.commit()
    db.refresh(record)
    return record


def revoke_token(
    db: Session,
    *,
    token_id: str,
    actor_id: int,
    actor_email: str,
    actor_role: str,
) -> IntegrationToken:
    record = db.scalar(
        select(IntegrationToken).where(IntegrationToken.token_id == token_id)
    )
    if not record:
        raise IntegrationTokenNotFoundError("Integration token not found.")
    record.is_active = False
    audit_service.log_action(
        db,
        action="integration_token_revoked",
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="integration_token",
        target_id=record.token_id,
        details={"name": record.name, "source_name": record.source_name},
    )
    db.commit()
    db.refresh(record)
    return record
