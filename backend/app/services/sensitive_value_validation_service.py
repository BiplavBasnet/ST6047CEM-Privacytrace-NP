"""Value validators for sensitive-data candidates.

Returns explainable validation results with positive/negative signals.
Does not persist raw values.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from app.services.taxonomy_validator_service import luhn_valid, normalize_identifier


@dataclass
class ValidationResult:
    valid: bool
    validation_score: float
    positive_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)
    validator_id: str = "generic"
    limitations: list[str] = field(default_factory=list)


_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_NEPAL_PHONE_RE = re.compile(r"^(?:\+?977)?9[78]\d{8}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TIMESTAMP_LIKE = re.compile(r"^1[5-9]\d{8,12}$")
_MASKED_RE = re.compile(r"(?:\*{2,}|\[\s*masked\s*\]|x{4,})", re.I)
_AUTH_FIELD_HINTS = ("authorization", "password", "pin", "otp", "token", "secret", "api_key", "jwt")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _field_hint(context: dict[str, Any]) -> str:
    return str(
        context.get("field_name")
        or context.get("json_path")
        or context.get("header_name")
        or ""
    ).casefold()


def validate_candidate(
    value: Any,
    taxonomy_type: str,
    source_context: dict[str, Any] | None = None,
) -> ValidationResult:
    context = source_context or {}
    text = str(value or "").strip()
    field = _field_hint(context)
    t = taxonomy_type.casefold()

    if not text:
        return ValidationResult(False, 0.0, negative_signals=["empty_value"], validator_id="nonempty")

    if _MASKED_RE.search(text) or text.startswith("[") and "masked" in text.casefold():
        return ValidationResult(
            False,
            0.1,
            negative_signals=["already_masked_pattern"],
            validator_id="masked_guard",
            limitations=["Already-masked values are not treated as fresh raw exposure."],
        )

    if t in {"phone_number", "nepal_phone"}:
        return _validate_phone(text, field)
    if t in {"payment_card_number", "card_number", "pan"}:
        return _validate_card(text, field)
    if t in {"jwt", "jwt_token"}:
        return _validate_jwt(text)
    if t in {"api_key", "merchant_api_key", "payment_gateway_key"}:
        return _validate_api_key(text, field)
    if t in {"email_address", "email"}:
        return _validate_email(text, field)
    if t in {"otp", "pin"}:
        return _validate_otp_pin(text, field, t)
    if t in {"password", "plaintext_password"}:
        return _validate_password(text, field)
    if t in {"private_key"}:
        return _validate_private_key(text)
    if t in {"transaction_reference", "transaction_ref", "wallet_identifier", "wallet_id"}:
        return _validate_financial_ref(text, field, t)
    return ValidationResult(
        True,
        0.55,
        positive_signals=["generic_nonempty"],
        negative_signals=[],
        validator_id="generic",
        limitations=["No specialised validator for this taxonomy type."],
    )


def _validate_phone(text: str, field: str) -> ValidationResult:
    compact = normalize_identifier(text)
    positives: list[str] = []
    negatives: list[str] = []
    if _TIMESTAMP_LIKE.match(compact) and "phone" not in field and "mobile" not in field:
        negatives.append("timestamp_like_number")
        return ValidationResult(False, 0.15, positives, negatives, "phone_nepal", ["Rejected as timestamp-like."])
    if field in {"build_number", "request_id", "sequence", "counter"}:
        negatives.append("unrelated_field_name")
        return ValidationResult(False, 0.1, positives, negatives, "phone_nepal")
    if _NEPAL_PHONE_RE.match(compact) or re.fullmatch(r"9[78]\d{8}", compact):
        positives.append("nepal_prefix_length")
        if "phone" in field or "mobile" in field:
            positives.append("field_name_support")
        return ValidationResult(True, 0.9 if positives else 0.75, positives, negatives, "phone_nepal")
    if compact.isdigit() and len(compact) in {10, 11, 12, 13}:
        positives.append("digit_length_plausible")
        return ValidationResult(True, 0.55, positives, negatives + ["non_nepal_prefix"], "phone_generic", ["Prefix not Nepal-oriented."])
    negatives.append("phone_format_mismatch")
    return ValidationResult(False, 0.2, positives, negatives, "phone_nepal")


def _validate_card(text: str, field: str) -> ValidationResult:
    compact = normalize_identifier(text)
    if field in {"build_number", "request_id"}:
        return ValidationResult(False, 0.05, [], ["unrelated_field_name"], "luhn")
    if not compact.isdigit() or not 13 <= len(compact) <= 19:
        return ValidationResult(False, 0.1, [], ["digit_range_failed"], "luhn")
    if not luhn_valid(compact):
        return ValidationResult(False, 0.05, [], ["luhn_failed"], "luhn")
    positives = ["luhn_passed", "digit_range_ok"]
    if "card" in field or "pan" in field:
        positives.append("field_name_support")
    return ValidationResult(True, 0.92, positives, [], "luhn")


def _validate_jwt(text: str) -> ValidationResult:
    if _JWT_RE.match(text):
        return ValidationResult(True, 0.93, ["three_base64url_sections"], [], "jwt_structure", ["Structural validation only; token not authenticated."])
    return ValidationResult(False, 0.1, [], ["jwt_structure_failed"], "jwt_structure")


def _validate_api_key(text: str, field: str) -> ValidationResult:
    positives: list[str] = []
    negatives: list[str] = []
    if len(text) < 12:
        negatives.append("below_minimum_length")
        return ValidationResult(False, 0.15, positives, negatives, "api_key")
    has_vendor_prefix = bool(re.search(r"(?i)(pk[_-]|sk[_-]|AKIA|ghp_|glpat-)", text))
    ent = _entropy(text)
    # A recognized vendor prefix (e.g. sk_/sk-/pk_/AKIA/ghp_/glpat-) is a strong
    # structural signal on its own, even for low-entropy synthetic/test values
    # (e.g. "sk_test_AAAA...") that would otherwise look repetitive.
    if not has_vendor_prefix and ent < 2.5:
        negatives.append("low_entropy_credential_candidate")
        return ValidationResult(False, 0.2, positives, negatives, "api_key")
    positives.append("entropy_ok")
    if has_vendor_prefix or "key" in field or "secret" in field:
        positives.append("prefix_or_field_support")
        return ValidationResult(True, 0.88, positives, negatives, "api_key")
    if "key" not in field and "secret" not in field and "token" not in field:
        negatives.append("missing_field_context")
        return ValidationResult(False, 0.35, positives, negatives, "api_key", ["API-key candidate needs field/context support."])
    return ValidationResult(True, 0.7, positives, negatives, "api_key")


def _validate_email(text: str, field: str) -> ValidationResult:
    if _EMAIL_RE.match(text):
        positives = ["email_structure"]
        if "email" in field or "mail" in field:
            positives.append("field_name_support")
        return ValidationResult(True, 0.85, positives, [], "email")
    return ValidationResult(False, 0.1, [], ["email_structure_failed"], "email")


def _validate_otp_pin(text: str, field: str, kind: str) -> ValidationResult:
    compact = normalize_identifier(text)
    if not re.fullmatch(r"\d{4,8}", compact):
        return ValidationResult(False, 0.1, [], ["digit_shape_failed"], kind)
    if not any(h in field for h in ("otp", "pin", "passcode", "auth")):
        return ValidationResult(
            False,
            0.2,
            [],
            ["missing_auth_field_context"],
            kind,
            ["OTP/PIN requires strong authentication field-name support."],
        )
    return ValidationResult(True, 0.75, ["digit_shape_ok", "auth_field_support"], [], kind)


def _validate_password(text: str, field: str) -> ValidationResult:
    if not any(h in field for h in ("password", "passwd", "secret")) and len(text) < 6:
        return ValidationResult(False, 0.2, [], ["weak_password_context"], "password")
    return ValidationResult(True, 0.7, ["password_context_or_length"], [], "password")


def _validate_private_key(text: str) -> ValidationResult:
    if "BEGIN" in text and "PRIVATE KEY" in text:
        return ValidationResult(True, 0.95, ["pem_private_key_marker"], [], "private_key")
    return ValidationResult(False, 0.1, [], ["pem_marker_missing"], "private_key")


def _validate_financial_ref(text: str, field: str, kind: str) -> ValidationResult:
    positives: list[str] = []
    negatives: list[str] = []
    upper = text.upper()
    if kind.startswith("wallet") and ("WALLET" in upper or "WAL" in upper or "wallet" in field):
        positives.append("wallet_format_or_field")
        return ValidationResult(True, 0.88, positives, negatives, kind)
    if "TXN" in upper or "transaction" in field or "txn" in field:
        positives.append("txn_format_or_field")
        return ValidationResult(True, 0.85, positives, negatives, kind)
    if len(text) >= 6:
        positives.append("identifier_length")
        return ValidationResult(True, 0.55, positives, negatives + ["weak_format"], kind, ["Format weakly matched."])
    negatives.append("financial_ref_too_short")
    return ValidationResult(False, 0.15, positives, negatives, kind)
