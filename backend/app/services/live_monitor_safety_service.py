"""Safety scanner for Live Privacy Monitor events.

The scanner returns masked output and detection metadata. It never returns
raw values outside raw-value hashes used for traceability.

Live events are INGESTED evidence (raw log/event text from an external
system). This module only masks/flags raw sensitive values; it does NOT
reject events for certainty/blame wording (e.g. "confirmed breach",
"attacker accessed data") since that text may be an attributed quote from
the source system, not a PrivacyTrace-generated claim. PrivacyTrace's own
narrative output (alert summaries, reports, AI suggestions) is separately
constrained by `report_safety_service` / `ai_output_safety_service`. See
docs/INPUT_OUTPUT_SAFETY_SEPARATION.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.services import detection_service

_RE_AUTH_HEADER = re.compile(r'(?i)(?:Authorization|authorization)(?:\\"|")?\s*[:=]\s*(?:\\"|")?Bearer\s+[^\s,;}\"]+')
_RE_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_RE_PASSWORD_HASH = re.compile(r'(?i)\bpassword[_-]?hash(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+')
_RE_PASSWORD = re.compile(r'(?i)\b(password|passwd|pwd)(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+')
_RE_ACCESS_TOKEN = re.compile(r'(?i)\b(access[_-]?token|auth[_-]?token|refresh[_-]?token)(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+')
_RE_SESSION = re.compile(r'(?i)\bsession[_-]?token(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]+')
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_RE_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_RE_API_KEY = re.compile(
    r'(?i)\b(?:pk|sk)[_-](?:live|test|prod|dev|np)?[_-]?[A-Za-z0-9][A-Za-z0-9_\-]{7,}\b|\b(?:pk|sk)-[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9_]+\b|\bglpat-[A-Za-z0-9_\-]+\b'
)
_RE_TRANSACTION = re.compile(r"\bTXN-NP-[0-9A-Z]+(?:-[0-9A-Z]+)*(?![-A-Z0-9])\b")
_RE_WALLET = re.compile(r"\bWALLET-NP-[0-9A-Z]+\b", re.IGNORECASE)
_RE_WALLET_GENERIC = re.compile(r"\bWAL[A-Z0-9]{6,}\b", re.IGNORECASE)
_RE_NEPAL_PHONE = re.compile(r"\b98[0-9]{8}\b")
_RE_CREDENTIAL_USERNAME = re.compile(r'(?i)\b(username|user_name|uname|login)(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]{3,}')
_RE_MQTT_MARKER = re.compile(r"(?i)\bmqtt\b")
_RE_MQTT_NAME_FIELD = re.compile(r'(?i)\bname(?:\\"|")?\s*[:=]\s*(?:\\"|")?[^\s,;}\"]{3,}')


@dataclass
class LiveSensitiveMatch:
    start: int
    end: int
    sensitive_type: str
    raw_value_hash: str | None
    masked_value: str
    severity: str
    confidence: float = 0.92


@dataclass
class LiveSafetyResult:
    safe: bool
    masked_text: str
    matches: list[LiveSensitiveMatch] = field(default_factory=list)
    violation_codes: list[str] = field(default_factory=list)
    reason: str | None = None


def _mask_phone(raw: str) -> str:
    if len(raw) <= 6:
        return "*" * len(raw)
    return f"{raw[:3]}****{raw[-3:]}"


def _mask_transaction(raw: str) -> str:
    parts = raw.rsplit("-", 1)
    if len(parts) == 2 and parts[0]:
        return f"{parts[0]}-****"
    return "txn_[masked]"


def _hash(raw: str, sensitive_type: str = "generic") -> str | None:
    """HMAC fingerprint only — never fall back to unkeyed SHA-256."""

    return detection_service.fingerprint_for_detection(raw, sensitive_type)


def _mqtt_name_field_matches(text: str) -> list[LiveSensitiveMatch]:
    matches: list[LiveSensitiveMatch] = []
    for marker in _RE_MQTT_MARKER.finditer(text or ""):
        window_start = marker.end()
        window_end = min(len(text), marker.end() + 320)
        window = text[window_start:window_end]
        for item in _RE_MQTT_NAME_FIELD.finditer(window):
            raw = item.group(0)
            matches.append(
                LiveSensitiveMatch(
                    start=window_start + item.start(),
                    end=window_start + item.end(),
                    sensitive_type="credential_username",
                    raw_value_hash=_hash(raw, "credential_username"),
                    masked_value="username_[masked]",
                    severity="medium",
                    confidence=0.82,
                )
            )
    return matches


def _candidate_matches(text: str) -> list[LiveSensitiveMatch]:
    specs = [
        (_RE_AUTH_HEADER, "authorization_header", "authorization_[masked]", "critical", 0.96),
        (_RE_PRIVATE_KEY, "private_key", "private_key_[masked]", "critical", 0.98),
        (_RE_PASSWORD_HASH, "password_hash", "password_hash_[masked]", "critical", 0.97),
        (_RE_PASSWORD, "password", "password_[masked]", "critical", 0.96),
        (_RE_ACCESS_TOKEN, "access_token", "token_[masked]", "critical", 0.94),
        (_RE_SESSION, "session_token", "session_token_[masked]", "critical", 0.95),
        (_RE_JWT, "jwt_token", "jwt_[masked]", "critical", 0.95),
        (_RE_BEARER, "bearer_token", "bearer_[masked]", "critical", 0.95),
        (_RE_API_KEY, "api_key", "api_key_[masked]", "critical", 0.94),
        (_RE_TRANSACTION, "transaction_ref", None, "high", 0.93),
        (_RE_WALLET, "wallet_id", "WALLET-NP-****", "high", 0.93),
        (_RE_WALLET_GENERIC, "wallet_id", "wallet_[masked]", "high", 0.90),
        (_RE_CREDENTIAL_USERNAME, "credential_username", "username_[masked]", "medium", 0.82),
        (_RE_NEPAL_PHONE, "nepal_phone", None, "high", 0.92),
    ]
    matches: list[LiveSensitiveMatch] = []
    for pattern, sensitive_type, fixed_mask, severity, confidence in specs:
        for item in pattern.finditer(text or ""):
            raw = item.group(0)
            if sensitive_type == "nepal_phone":
                masked = _mask_phone(raw)
            elif sensitive_type == "transaction_ref":
                masked = _mask_transaction(raw)
            else:
                masked = fixed_mask or "[masked]"
            matches.append(
                LiveSensitiveMatch(
                    start=item.start(),
                    end=item.end(),
                    sensitive_type=sensitive_type,
                    raw_value_hash=_hash(raw, sensitive_type),
                    masked_value=masked,
                    severity=severity,
                    confidence=confidence,
                )
            )
    matches.extend(_mqtt_name_field_matches(text or ""))
    return _dedupe_overlaps(matches)


def _dedupe_overlaps(matches: list[LiveSensitiveMatch]) -> list[LiveSensitiveMatch]:
    ordered = sorted(matches, key=lambda m: (-(m.end - m.start), m.start))
    kept: list[LiveSensitiveMatch] = []
    for match in ordered:
        if any(match.start >= other.start and match.end <= other.end for other in kept):
            continue
        kept.append(match)
    return sorted(kept, key=lambda m: m.start)


def _apply_masks(text: str, matches: list[LiveSensitiveMatch]) -> str:
    result = text or ""
    for match in sorted(matches, key=lambda m: m.start, reverse=True):
        result = result[: match.start] + match.masked_value + result[match.end :]
    return result


def scan_and_mask_text(text: str) -> LiveSafetyResult:
    matches = _candidate_matches(text)
    masked = _apply_masks(text, matches)
    return LiveSafetyResult(
        safe=True,
        masked_text=masked,
        matches=matches,
        violation_codes=list(dict.fromkeys(m.sensitive_type for m in matches)),
    )


def assert_masked_output_safe(masked_text: str) -> bool:
    return len(_candidate_matches(masked_text)) == 0




