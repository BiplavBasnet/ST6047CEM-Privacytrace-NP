"""Central fingerprinting for sensitive-value comparison.

There is exactly one supported stable-fingerprint method across the engine:
keyed HMAC-SHA256 over the taxonomy type and a normalised value
(`taxonomy_validator_service.hmac_fingerprint`, keyed by
`settings.detection_hmac_key`). This module is the single call site the rest
of the engine should use so every finding shares one fingerprint contract
instead of the legacy split between plain SHA-256 (`detection_service.
hash_raw_value`, prefixed `sha256:`) and HMAC (contextual/taxonomy path).

Plain SHA-256 digests of predictable, low-entropy identifiers (phone
numbers, citizenship numbers, dates of birth, account numbers) are
brute-forceable and must never be treated as equivalent to an HMAC
fingerprint for comparison or deduplication purposes; `is_legacy_sha256`
exists so callers can detect and refuse that comparison.
"""

from __future__ import annotations

from typing import Any

from app.config import get_settings
from app.services.taxonomy_validator_service import hmac_fingerprint

FINGERPRINT_METHOD = "hmac_sha256_v1"
FINGERPRINT_VERSION = "v1"

_LEGACY_SHA256_PREFIX = "sha256:"
_HMAC_PREFIX = "HMAC-SHA256-V1:"


class FingerprintUnavailableError(RuntimeError):
    """Raised when a stable fingerprint cannot be produced (e.g. no HMAC key)."""


def fingerprint(value: Any, taxonomy_type: str) -> dict[str, str]:
    """Produce the one supported stable fingerprint for `value`.

    Returns `{"fingerprint", "method", "version"}`. Raises
    `FingerprintUnavailableError` rather than silently falling back to an
    unkeyed hash if `DETECTION_HMAC_KEY` is not configured.
    """

    key = get_settings().detection_hmac_key
    if not key:
        raise FingerprintUnavailableError(
            "DETECTION_HMAC_KEY is not configured; refusing to fingerprint with an unkeyed hash."
        )
    digest = hmac_fingerprint(value, taxonomy_type, key)
    return {
        "fingerprint": digest,
        "method": FINGERPRINT_METHOD,
        "version": FINGERPRINT_VERSION,
    }


def is_legacy_sha256(hash_value: str | None) -> bool:
    """True if `hash_value` looks like the legacy unkeyed SHA-256 format.

    Legacy `sha256:<hex>` digests (from `detection_service.hash_raw_value`)
    must never be compared against, or treated as equivalent to, an
    HMAC-SHA256 fingerprint produced by `fingerprint()` — they use no key and
    are brute-forceable for predictable identifiers.
    """

    return bool(hash_value) and str(hash_value).startswith(_LEGACY_SHA256_PREFIX)


def is_hmac_fingerprint(hash_value: str | None) -> bool:
    return bool(hash_value) and str(hash_value).startswith(_HMAC_PREFIX)
