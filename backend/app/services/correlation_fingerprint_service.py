"""Keyed, versioned fingerprints for policy-designated correlation IDs."""

from __future__ import annotations

from typing import Any

from app.services import sensitive_fingerprint_service

_POLICY_TYPES = {
    "trace_id": "correlation_trace_id",
    "request_id": "correlation_request_id",
    "correlation_id": "correlation_id",
    "transaction_reference": "transaction_reference",
    "session_reference": "session_reference",
}


def fingerprint(value: Any, identifier_type: str) -> dict[str, str] | None:
    """Return the central HMAC contract, or no correlatable value if unavailable."""

    text = str(value or "").strip()
    taxonomy_type = _POLICY_TYPES.get(identifier_type)
    if not text or taxonomy_type is None:
        return None
    try:
        return sensitive_fingerprint_service.fingerprint(text, taxonomy_type)
    except sensitive_fingerprint_service.FingerprintUnavailableError:
        return None


def fingerprint_keys(values: dict[str, Any]) -> dict[str, str]:
    """Fingerprint designated identifiers; retain no raw identifier values."""

    result: dict[str, str] = {}
    method: str | None = None
    version: str | None = None
    for key in _POLICY_TYPES:
        item = fingerprint(values.get(key), key)
        if item:
            result[f"{key}_fingerprint"] = item["fingerprint"]
            method, version = item["method"], item["version"]
    if method:
        result["fingerprint_method"] = method
        result["fingerprint_version"] = version or ""
    return result
