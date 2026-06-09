"""JWT authentication, login, and public registration helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import UserRole
from app.models.user import User
from app.services import key_management_service, password_service, user_service

TOKEN_TYPE_BEARER = "bearer"
JWT_ALG_ASYMMETRIC = "RS256"
ALLOWED_REGISTRATION_ROLE = UserRole.VIEWER


class AuthError(Exception):
    """Base authentication error."""


class InvalidCredentialsError(AuthError):
    pass


class InactiveUserError(AuthError):
    pass


class InvalidTokenError(AuthError):
    pass


class RegistrationDisabledError(AuthError):
    pass


class RegistrationRejectedError(AuthError):
    """Registration failed for a safe, non-credential reason."""

    def __init__(self, reason: str, message: str):
        self.reason = reason
        super().__init__(message)


def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


def resolved_registration_role() -> UserRole:
    """Public registration may only assign the least-privileged viewer role."""
    settings = get_settings()
    configured = (settings.default_registration_role or "").strip().lower()
    if configured != ALLOWED_REGISTRATION_ROLE.value:
        raise RegistrationRejectedError(
            "invalid_default_role",
            "Self-registration is misconfigured. Contact an administrator.",
        )
    return ALLOWED_REGISTRATION_ROLE


def _jwt_use_asymmetric() -> bool:
    return key_management_service.jwt_keys_configured()


def _read_pem(path_str: str | None) -> bytes:
    settings = get_settings()
    from app.config import get_backend_root

    if not path_str:
        raise InvalidTokenError("JWT key path not configured")
    path = Path(path_str)
    if not path.is_absolute():
        path = get_backend_root() / path
    return path.read_bytes()


def create_access_token(*, user: User) -> str:
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "ver": int(user.token_version or 0),
        "exp": expire,
    }
    headers: dict[str, str] = {}
    if _jwt_use_asymmetric():
        headers["kid"] = key_management_service.active_kid()
        private_pem = _read_pem(settings.jwt_private_key_path)
        return jwt.encode(
            payload,
            private_pem,
            algorithm=JWT_ALG_ASYMMETRIC,
            headers=headers,
        )
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        if _jwt_use_asymmetric():
            public_pem = _read_pem(settings.jwt_public_key_path)
            return jwt.decode(token, public_pem, algorithms=[JWT_ALG_ASYMMETRIC])
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError("Invalid or expired token") from exc


def authenticate_user(db: Session, *, email: str, password: str) -> User:
    normalised = normalise_email(email)
    user = db.scalar(select(User).where(User.email == normalised))
    if user is None or not user.password_hash:
        raise InvalidCredentialsError("Invalid email or password")
    if not user.is_active:
        raise InactiveUserError("User account is inactive")
    if not password_service.verify_password(password, user.password_hash):
        raise InvalidCredentialsError("Invalid email or password")
    user.last_login_at = datetime.now(UTC)
    if password_service.detect_algorithm(user.password_hash) == password_service.PREFERRED_ALGORITHM:
        user.password_hash_algorithm = password_service.PREFERRED_ALGORITHM
    db.flush()
    return user


def register_user(
    db: Session,
    *,
    full_name: str,
    email: str,
    password: str,
    invite_token: str | None = None,
) -> User:
    from app.services import organisation_access_service as org_access

    settings = get_settings()
    token = (invite_token or "").strip() or None
    if token:
        try:
            user, _membership, _invitation = org_access.accept_invitation(
                db,
                token=token,
                full_name=full_name,
                email=email,
                password=password,
            )
            return user
        except org_access.OrganisationAccessError as extra:
            reason = "duplicate_email" if extra.status_code == 409 else "invalid_invitation"
            raise RegistrationRejectedError(reason, str(extra)) from extra

    if settings.invite_only_registration or not settings.self_registration_enabled:
        raise RegistrationDisabledError("Self-registration is currently unavailable.")
    if settings.email_verification_required:
        # No mail provider is wired; refuse rather than pretend a message was sent.
        raise RegistrationRejectedError(
            "email_verification_unsupported",
            "Email verification is required but no verification provider is configured.",
        )
    role = resolved_registration_role()
    normalised = normalise_email(email)
    if not normalised or "@" not in normalised:
        raise RegistrationRejectedError("invalid_email", "Invalid email format")
    try:
        return user_service.create_user(
            db,
            name=full_name.strip(),
            email=normalised,
            role=role,
            password=password,
        )
    except user_service.DuplicateEmailError as exc:
        raise RegistrationRejectedError(
            "duplicate_email",
            "An account with this email already exists.",
        ) from exc


def get_user_from_token(db: Session, token: str) -> User:
    payload = decode_access_token(token)
    sub = payload.get("sub")
    if not sub:
        raise InvalidTokenError("Invalid token subject")
    try:
        user_id = int(sub)
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError("Invalid token subject") from exc
    user = db.get(User, user_id)
    if user is None:
        raise InvalidTokenError("User not found")
    if not user.is_active:
        raise InactiveUserError("User account is inactive")
    token_version = payload.get("ver", 0)
    if int(token_version or 0) != int(user.token_version or 0):
        raise InvalidTokenError("Session is no longer valid")
    return user


def user_to_public_dict(user: User) -> dict:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
    }
