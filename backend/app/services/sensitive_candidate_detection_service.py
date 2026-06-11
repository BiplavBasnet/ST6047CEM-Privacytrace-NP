"""Unified sensitive-value candidate detection.

Produces *candidates only*: possible sensitive-value matches found either by
regex over free text (logs, request/response bodies, headers rendered as
text) or by field-name alias matching over structured dicts (JSON bodies,
SIEM/ScannerBridge structured events).

This module deliberately does not:
  - decide whether a candidate is a real value (see
    `sensitive_value_validation_service`),
  - decide whether presence is an unsafe exposure (see
    `sensitive_exposure_policy_service`),
  - create alerts or persist raw values.

`raw_value` on `SensitiveCandidate` is kept only for the in-process caller
(the exposure engine) to validate, mask and fingerprint. Callers must not
serialise it; use `SensitiveCandidate.safe_dict()` for any logging/debugging.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import yaml

from app.config import resolve_rules_dir
from app.services.sensitive_data_taxonomy_service import canonical_type_name

DETECTOR_VERSION = "unified_candidate_v1"

# Field-name aliases used only to decide *which raw_type_hint* a structured
# field probably represents. This is intentionally separate from the Nepal
# taxonomy registry's context-term matching (`taxonomy_registry_service`) and
# from `sensitive_data_taxonomy_service`'s legacy-alias index: this table maps
# a field NAME to a raw detector type hint, not a type hint to a canonical
# taxonomy type. Keeping raw_type_hint distinct from taxonomy_type lets
# masking (keyed by legacy-style names in masking_rules.yaml) and taxonomy
# resolution (keyed by canonical names) both work off one candidate.
_FIELD_NAME_ALIASES: dict[str, str] = {
    "phone": "nepal_phone",
    "phone_number": "nepal_phone",
    "mobile": "nepal_phone",
    "mobile_number": "nepal_phone",
    "customer_phone": "nepal_phone",
    "contact_number": "nepal_phone",
    "email": "email",
    "email_address": "email",
    "customer_email": "email",
    "card_number": "card_number",
    "pan": "card_number",
    "payment_card": "card_number",
    "credit_card": "card_number",
    "card_pan": "card_number",
    "otp": "otp",
    "otp_code": "otp",
    "verification_code": "otp",
    "one_time_password": "otp",
    "pin": "pin",
    "pin_code": "pin",
    "atm_pin": "pin",
    "password": "password",
    "passwd": "password",
    "pwd": "password",
    "password_hash": "password_hash",
    "api_key": "api_key",
    "secret_key": "api_key",
    "merchant_api_key": "api_key",
    "payment_gateway_key": "api_key",
    "wallet_id": "wallet_id",
    "wallet": "wallet_id",
    "wallet_identifier": "wallet_id",
    "transaction_id": "transaction_ref",
    "transaction_ref": "transaction_ref",
    "txn_ref": "transaction_ref",
    "txn_id": "transaction_ref",
    "bank_account": "bank_account",
    "bank_account_number": "bank_account",
    "account_number": "bank_account",
    "citizenship": "citizenship",
    "citizenship_number": "citizenship",
    "national_id": "citizenship",
    "jwt": "jwt_token",
    "jwt_token": "jwt_token",
    "access_token": "access_token",
    "refresh_token": "refresh_token",
    "session_token": "session_token",
    "authorization": "authorization_header",
    "authorization_header": "authorization_header",
    "username": "credential_username",
    "user_name": "credential_username",
    "login": "credential_username",
    "private_key": "private_key",
    "full_name": "full_name",
    "customer_name": "full_name",
    "name": "full_name",
}

# Regex candidates that are safe to run over unstructured free text (logs,
# bodies rendered as strings). Loaded primarily from
# `app/rules/sensitive_data_rules.yaml`; a small set of additional
# "live-compatible" patterns not present in that YAML (but used historically
# by `live_monitor_safety_service`) are appended so free-text scanning stays
# consistent between the evidence path and the live/streaming path.
_EXTRA_TEXT_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("wallet_generic", "wallet_id", r"(?i)\bWAL[A-Z0-9]{6,}\b"),
    ("email_generic", "email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("card_number_generic", "card_number", r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b"),
)


@dataclass
class TextPattern:
    pattern_id: str
    raw_type_hint: str
    regex: re.Pattern[str]
    confidence: float = 0.85


@dataclass
class SensitiveCandidate:
    candidate_id: str
    raw_type_hint: str
    taxonomy_type: str
    field_name: str | None
    json_path: str | None
    source_location: str
    start: int | None
    end: int | None
    pattern_id: str | None
    detector_version: str
    raw_value: str = field(repr=False)

    def safe_dict(self) -> dict[str, Any]:
        """Debug/log-safe view: never includes `raw_value`."""

        return {
            "candidate_id": self.candidate_id,
            "raw_type_hint": self.raw_type_hint,
            "taxonomy_type": self.taxonomy_type,
            "field_name": self.field_name,
            "json_path": self.json_path,
            "source_location": self.source_location,
            "start": self.start,
            "end": self.end,
            "pattern_id": self.pattern_id,
            "detector_version": self.detector_version,
        }


@lru_cache(maxsize=1)
def load_text_patterns() -> tuple[TextPattern, ...]:
    path = resolve_rules_dir() / "sensitive_data_rules.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    patterns: list[TextPattern] = []
    for entry in data.get("rules") or []:
        patterns.append(
            TextPattern(
                pattern_id=str(entry["name"]),
                raw_type_hint=str(entry["sensitive_type"]),
                regex=re.compile(entry["pattern"]),
                confidence=float(entry.get("confidence", 0.85)),
            )
        )
    for pattern_id, raw_type_hint, pattern in _EXTRA_TEXT_PATTERNS:
        patterns.append(
            TextPattern(pattern_id=pattern_id, raw_type_hint=raw_type_hint, regex=re.compile(pattern), confidence=0.75)
        )
    return tuple(patterns)


def reset_pattern_cache() -> None:
    load_text_patterns.cache_clear()


def pattern_strength_for(pattern_id: str | None) -> float | None:
    """Declared rule confidence for a text pattern_id, or None for field-alias candidates."""

    if not pattern_id or pattern_id.startswith("field_alias:"):
        return None
    for pattern in load_text_patterns():
        if pattern.pattern_id == pattern_id:
            return pattern.confidence
    return None


def _new_candidate_id() -> str:
    return f"CAND-{uuid.uuid4().hex[:16].upper()}"


def _dedupe(candidates: list[SensitiveCandidate]) -> list[SensitiveCandidate]:
    """Drop candidates fully contained inside a longer/equal match at the same span origin."""

    text_candidates = [c for c in candidates if c.start is not None and c.end is not None]
    other_candidates = [c for c in candidates if c.start is None or c.end is None]
    ordered = sorted(text_candidates, key=lambda c: (-(c.end - c.start), c.start))
    kept: list[SensitiveCandidate] = []
    for candidate in ordered:
        if any(
            candidate.start >= other.start
            and candidate.end <= other.end
            and candidate is not other
            for other in kept
        ):
            continue
        kept.append(candidate)
    kept.sort(key=lambda c: c.start)
    return kept + other_candidates


def detect_text_candidates(
    text: str | None,
    *,
    source_location: str = "text",
) -> list[SensitiveCandidate]:
    if not text:
        return []
    candidates: list[SensitiveCandidate] = []
    for pattern in load_text_patterns():
        for match in pattern.regex.finditer(text):
            raw_value = match.group(0)
            candidates.append(
                SensitiveCandidate(
                    candidate_id=_new_candidate_id(),
                    raw_type_hint=pattern.raw_type_hint,
                    taxonomy_type=canonical_type_name(pattern.raw_type_hint),
                    field_name=None,
                    json_path=None,
                    source_location=source_location,
                    start=match.start(),
                    end=match.end(),
                    pattern_id=pattern.pattern_id,
                    detector_version=DETECTOR_VERSION,
                    raw_value=raw_value,
                )
            )
    return _dedupe(candidates)


def _normalise_field(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")


def _flatten_fields(value: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, str, Any]]:
    """Yield (field_name, json_path, value) for scalar leaves of a structured payload."""

    if depth > 4:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_fields(item, path, depth + 1)
        return
    if isinstance(value, list):
        for index, item in enumerate(value[:25]):
            path = f"{prefix}[{index}]"
            yield from _flatten_fields(item, path, depth + 1)
        return
    if value is None or isinstance(value, (dict, list)):
        return
    leaf_name = prefix.rsplit(".", 1)[-1].split("[", 1)[0]
    yield leaf_name, prefix, value


def detect_structured_candidates(
    fields: dict[str, Any] | None,
    *,
    source_location: str = "structured_field",
) -> list[SensitiveCandidate]:
    if not fields:
        return []
    candidates: list[SensitiveCandidate] = []
    for leaf_name, json_path, value in _flatten_fields(fields):
        alias = _FIELD_NAME_ALIASES.get(_normalise_field(leaf_name))
        if alias is None:
            continue
        text_value = str(value)
        if not text_value.strip():
            continue
        candidates.append(
            SensitiveCandidate(
                candidate_id=_new_candidate_id(),
                raw_type_hint=alias,
                taxonomy_type=canonical_type_name(alias),
                field_name=leaf_name,
                json_path=json_path,
                source_location=source_location,
                start=None,
                end=None,
                pattern_id=f"field_alias:{_normalise_field(leaf_name)}",
                detector_version=DETECTOR_VERSION,
                raw_value=text_value,
            )
        )
    return candidates


def detect_candidates(
    *,
    text: str | None = None,
    structured: dict[str, Any] | None = None,
    text_source_location: str = "text",
    structured_source_location: str = "structured_field",
) -> list[SensitiveCandidate]:
    """Run both text and structured detection and return combined candidates."""

    return detect_text_candidates(text, source_location=text_source_location) + detect_structured_candidates(
        structured, source_location=structured_source_location
    )
