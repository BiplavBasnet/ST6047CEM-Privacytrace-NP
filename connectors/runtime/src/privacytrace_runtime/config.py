"""Stub settings for the standalone runtime connector.

resolve_rules_dir() points at packaged YAML. detection_hmac_key is empty so
fingerprinting stays fail-closed (FingerprintUnavailableError is handled).
This package must never ship DETECTION_HMAC_KEY or a demo HMAC.
"""

from __future__ import annotations

from pathlib import Path


def resolve_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


class _Settings:
    detection_hmac_key = ""


def get_settings() -> _Settings:
    return _Settings()
