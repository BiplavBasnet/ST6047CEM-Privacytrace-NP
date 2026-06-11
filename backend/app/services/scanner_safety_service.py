"""ScannerBridge-NP safety: strip raw secrets, remask values, reject unsalvageable payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.services import audit_safety_service, masking_service

FORBIDDEN_KEYS = frozenset(
    {
        "raw",
        "Raw",
        "RAW",
        "raw_value",
        "secret",
        "Secret",
        "full_token",
        "private_key",
        "password",
        "password_hash",
        "plaintext_password",
        "passwd",
        "pwd",
        "session_token",
        "authorization",
        "Authorization",
    }
)

_RE_NEPAL_PHONE = re.compile(r"\b98[0-9]{8}\b")
_RE_WALLET = re.compile(r"(?i)\bWALLET-NP-[A-Z0-9]+\b")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_RE_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{8,}\b")
_RE_AUTH_HEADER = re.compile(r'(?i)(?:Authorization|authorization)(?:\\"|")?\s*[:=]\s*(?:\\"|")?\S+')
_RE_API_KEY = re.compile(
    r'(?i)\b(?:pk|sk)[_-](?:live|test|prod|dev|np)?[_-]?[A-Za-z0-9][A-Za-z0-9_\-]{7,}\b|\b(?:pk|sk)-[A-Za-z0-9]{20,}\b|AKIA[0-9A-Z]{16}\b|ghp_[A-Za-z0-9]+\b|glpat-[A-Za-z0-9]+\b|xoxb-[A-Za-z0-9]+\b'
)
_RE_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_RE_PASSWORD_ASSIGN = re.compile(r'(?i)\b(password|passwd|pwd)(?:\\"|")?\s*[:=]\s*(?:\\"|")?\S+')
_RE_PASSWORD_HASH = re.compile(r'(?i)\bpassword[_-]?hash(?:\\"|")?\s*[:=]\s*(?:\\"|")?\S+')
_RE_ACCESS_TOKEN = re.compile(r'(?i)\b(access[_-]?token|auth[_-]?token|refresh[_-]?token)(?:\\"|")?\s*[:=]\s*(?:\\"|")?\S+')

GENERIC_REJECT = (
    "Scanner payload contains unsafe raw sensitive values that cannot be safely sanitised. "
    "Provide masked or redacted values only."
)


@dataclass
class ScannerSafetyResult:
    safe: bool
    violation_codes: list[str] = field(default_factory=list)
    reason: str | None = None
    sanitised_payload: Any | None = None


def _violation_codes_for_text(text: str) -> list[str]:
    """Return hard-block violation codes for INPUT text.

    This only flags raw secrets/sensitive values that must be masked or
    rejected. It deliberately does NOT scan for overclaim/certainty
    wording (e.g. "confirmed breach") because scanner findings are
    ingested evidence that may legitimately quote a source tool's own
    description. Output claim safety for PrivacyTrace-generated text is
    handled separately by `report_safety_service` / `ai_output_safety_service`.
    See docs/INPUT_OUTPUT_SAFETY_SEPARATION.md.
    """
    codes = audit_safety_service.scan_text_for_sensitive(text)
    if _RE_NEPAL_PHONE.search(text):
        codes.append("nepal_phone")
    if _RE_WALLET.search(text):
        codes.append("raw_wallet_id")
    if _RE_JWT.search(text):
        codes.append("jwt_token")
    if _RE_BEARER.search(text):
        codes.append("bearer_token")
    if _RE_AUTH_HEADER.search(text):
        codes.append("authorization_header")
    if _RE_API_KEY.search(text):
        codes.append("api_key")
    if _RE_PRIVATE_KEY.search(text):
        codes.append("private_key_block")
    if _RE_PASSWORD_ASSIGN.search(text):
        codes.append("password_field")
    if _RE_PASSWORD_HASH.search(text):
        codes.append("password_hash_field")
    if _RE_ACCESS_TOKEN.search(text):
        codes.append("access_token_field")
    return list(dict.fromkeys(codes))


def remask_string(value: str) -> tuple[str, list[str]]:
    """Attempt to remask a string; return (masked, violation_codes_if_unsafe)."""
    violations = _violation_codes_for_text(value)
    if not violations:
        return value, []

    result = value
    if _RE_NEPAL_PHONE.search(result):
        result = _RE_NEPAL_PHONE.sub(
            lambda m: masking_service.mask_value("nepal_phone", m.group(0)),
            result,
        )
    if _RE_WALLET.search(result):
        result = _RE_WALLET.sub("WALLET-NP-****", result)
    if _RE_JWT.search(result):
        result = _RE_JWT.sub("jwt_[masked]", result)
    if _RE_BEARER.search(result):
        result = _RE_BEARER.sub("bearer_[masked]", result)
    if _RE_AUTH_HEADER.search(result):
        result = _RE_AUTH_HEADER.sub("Authorization: [masked]", result)
    if _RE_API_KEY.search(result):
        result = _RE_API_KEY.sub("key_[masked]", result)
    if _RE_PRIVATE_KEY.search(result):
        result = _RE_PRIVATE_KEY.sub("private_key_[masked]", result)
    if _RE_PASSWORD_ASSIGN.search(result):
        result = _RE_PASSWORD_ASSIGN.sub(r"\1=[masked]", result)
    if _RE_PASSWORD_HASH.search(result):
        result = _RE_PASSWORD_HASH.sub("password_hash=[masked]", result)
    if _RE_ACCESS_TOKEN.search(result):
        result = _RE_ACCESS_TOKEN.sub(r"\1=[masked]", result)

    # Scanner exports often use redacted forms such as pk_test_****. Treat only
    # the API-key violation as resolved when masking markers are present; other
    # hard-block violations in the same text still reject the payload.
    if "api_key" in violations and "*" in result:
        violations = [code for code in violations if code != "api_key"]

    # If high-risk raw patterns were present, reject instead of auto-accepting.
    hard_block_codes = {
        "nepal_phone",
        "jwt_token",
        "bearer_token",
        "authorization_header",
        "private_key_block",
        "password_field",
        "password_hash_field",
        "api_key",
        "access_token_field",
    }
    if any(code in hard_block_codes for code in violations):
        return result, list(dict.fromkeys(violations))

    remaining = _violation_codes_for_text(result)
    # Redacted values (e.g., pk_test_****) are acceptable for scanner imports.
    if remaining and set(remaining).issubset({"api_key", "api_key_raw"}) and "*" in result:
        return result, []
    if remaining:
        return result, remaining
    return result, []


def _sanitize_value(value: Any, *, in_forbidden_parent: bool = False) -> tuple[Any, list[str]]:
    if value is None:
        return None, []
    if isinstance(value, str):
        if in_forbidden_parent:
            return None, ["forbidden_key_value"]
        return remask_string(value)
    if isinstance(value, (int, float, bool)):
        return value, []
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        all_v: list[str] = []
        for key, sub in value.items():
            if key in FORBIDDEN_KEYS:
                all_v.append(f"dropped_key:{key}")
                continue
            clean, v = _sanitize_value(sub, in_forbidden_parent=False)
            if clean is not None:
                out[key] = clean
            all_v.extend(v)
        return out, all_v
    if isinstance(value, list):
        out_list: list[Any] = []
        all_v: list[str] = []
        for item in value:
            clean, v = _sanitize_value(item)
            if clean is not None:
                out_list.append(clean)
            all_v.extend(v)
        return out_list, all_v
    return value, []


def sanitize_payload(payload: Any) -> ScannerSafetyResult:
    clean, violations = _sanitize_value(payload)
    unique = list(dict.fromkeys(violations))
    hard_block_codes = {
        "nepal_phone",
        "jwt_token",
        "bearer_token",
        "authorization_header",
        "private_key_block",
        "password_field",
        "password_hash_field",
        "api_key",
        "access_token_field",
    }
    if any(v in hard_block_codes for v in unique):
        return ScannerSafetyResult(
            safe=False,
            violation_codes=unique,
            reason=GENERIC_REJECT,
        )
    if unique and any(
        v.startswith("dropped_key:") or v == "forbidden_key_value" for v in unique
    ):
        return ScannerSafetyResult(
            safe=False,
            violation_codes=unique,
            reason=GENERIC_REJECT,
        )
    still_unsafe = []
    if isinstance(clean, (dict, list)):
        import json

        blob = json.dumps(clean, default=str)
        still_unsafe = _violation_codes_for_text(blob)
        # Allow already-masked API key patterns in redacted scanner payloads.
        if still_unsafe and set(still_unsafe) == {"api_key_raw"} and "*" in blob:
            still_unsafe = []
    elif isinstance(clean, str):
        _, still_unsafe = remask_string(clean)

    if still_unsafe:
        return ScannerSafetyResult(
            safe=False,
            violation_codes=unique + still_unsafe,
            reason=GENERIC_REJECT,
        )
    return ScannerSafetyResult(safe=True, sanitised_payload=clean, violation_codes=unique)
