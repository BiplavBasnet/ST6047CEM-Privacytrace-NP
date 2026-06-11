"""Password hashing (PBKDF2-HMAC-SHA256) with bcrypt verifier compatibility."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

import bcrypt

from app.config import get_settings

PREFERRED_ALGORITHM = "pbkdf2-sha256"
BCRYPT_ALGORITHM = "bcrypt"
PBKDF2_PREFIX = "$pbkdf2-sha256$"


def _pbkdf2_iterations() -> int:
    return get_settings().pbkdf2_iterations


def hash_password(plain_password: str) -> str:
    salt = os.urandom(16)
    iterations = _pbkdf2_iterations()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        plain_password.encode("utf-8"),
        salt,
        iterations,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"{PBKDF2_PREFIX}{iterations}${salt_b64}${digest_b64}"


def _verify_pbkdf2(plain_password: str, password_hash: str) -> bool:
    try:
        body = password_hash[len(PBKDF2_PREFIX) :]
        iterations_str, salt_b64, digest_b64 = body.split("$", 2)
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _verify_bcrypt(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except ValueError:
        return False


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if password_hash.startswith(PBKDF2_PREFIX):
        return _verify_pbkdf2(plain_password, password_hash)
    return _verify_bcrypt(plain_password, password_hash)


def detect_algorithm(password_hash: str) -> str:
    if password_hash.startswith(PBKDF2_PREFIX):
        return PREFERRED_ALGORITHM
    if password_hash.startswith("$2"):
        return BCRYPT_ALGORITHM
    return "unknown"
