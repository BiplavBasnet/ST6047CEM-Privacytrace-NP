"""Shared password strength rules for admin create and public registration."""

from __future__ import annotations

PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128


def validate_password_strength(value: str | None) -> str | None:
    if value is None:
        return value
    checks = (
        any(ch.islower() for ch in value),
        any(ch.isupper() for ch in value),
        any(ch.isdigit() for ch in value),
        any(not ch.isalnum() for ch in value),
    )
    if len(value) < PASSWORD_MIN_LENGTH or not all(checks):
        raise ValueError(
            "Password must be at least 10 characters and include uppercase, "
            "lowercase, digit, and symbol characters"
        )
    return value
