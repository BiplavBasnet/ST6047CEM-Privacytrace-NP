"""Phase 11.8 inbound integration safety validation.

This service enforces the strict privacy and safety contract for any
event ingested from an external SIEM/SOC tool. Raw sensitive values and
secret-bearing headers/password-like fields are rejected outright.
Masked values, evidence IDs, likely-cause wording, and attributed
certainty/blame quotes from the source system (e.g. a SOC ticket that
says "attacker accessed data") are all accepted: this boundary only
guards against *raw secrets*, not narrative wording. PrivacyTrace's own
generated claims (reports, AI suggestions, LLM investigation output)
are separately blocked from asserting unsupported certainty by
`report_safety_service` / `ai_output_safety_service` /
`llm_safety_service`. See docs/INPUT_OUTPUT_SAFETY_SEPARATION.md.

The validator never echoes the unsafe value back to the caller; it
returns a short, generic reason and the set of violation codes that the
audit log records (so SOC operators can debug their own mappings
without leaking secrets).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services import audit_safety_service

# Extra patterns that must always be rejected even if the central
# llm_safety_rules.yaml is loosened. These are belt-and-braces guards
# for the integration boundary.
_EXTRA_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("raw_wallet_id", re.compile(r"(?i)\bWAL[A-Z0-9]{6,}\b")),
    ("password_field", re.compile(r'(?i)"?(?:password|passwd|pwd)"?\s*[:=]\s*"?[^\s"]+')),
    ("password_hash_field", re.compile(r"(?i)password[_\-]?hash")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("session_token_field", re.compile(r'(?i)"?session[_\-]?token"?\s*[:=]\s*"?\S+')),
    ("access_token_field", re.compile(r'(?i)"?(?:access[_\-]?token|auth[_\-]?token|refresh[_\-]?token)"?\s*[:=]\s*"?\S+')),
    ("authorization_header_inline", re.compile(r'(?i)"?(?:Authorization|authorization)"?\s*[:=]\s*"?\S+')),
    ("api_key_inline", re.compile(r'(?i)\b(?:pk|sk)[_-](?:live|test|prod|dev|np)?[_-]?[A-Za-z0-9][A-Za-z0-9_\-]{7,}\b|\b(?:pk|sk)-[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9_]{8,}\b|\bglpat-[A-Za-z0-9_\-]{8,}\b')),
)

# Inputs known to be safe identifiers / wording that should never trigger.
_GENERIC_REJECT_REASON = (
    "Payload contains an unsafe raw sensitive value that cannot be safely masked. "
    "Send masked values only."
)


@dataclass
class IntegrationValidationResult:
    safe: bool
    violation_codes: list[str] = field(default_factory=list)
    reason: str | None = None


def _scan_string(text: str) -> list[str]:
    if not text:
        return []
    violations: list[str] = []
    violations.extend(audit_safety_service.scan_text_for_sensitive(text))
    for code, pattern in _EXTRA_SENSITIVE_PATTERNS:
        if pattern.search(text):
            violations.append(code)
    # de-duplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for v in violations:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def _walk(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return _scan_string(value)
    if isinstance(value, (int, float, bool)):
        return []
    if isinstance(value, dict):
        violations: list[str] = []
        for key, sub in value.items():
            if isinstance(key, str):
                violations.extend(_scan_string(key))
            violations.extend(_walk(sub))
        return violations
    if isinstance(value, (list, tuple, set)):
        violations = []
        for item in value:
            violations.extend(_walk(item))
        return violations
    # Fallback: serialize and scan.
    return _scan_string(json.dumps(value, default=str))


def validate_inbound_event(event: dict[str, Any]) -> IntegrationValidationResult:
    """Validate the canonical event dict (already-mapped form).

    The caller has already mapped vendor JSON into the canonical schema,
    so we scan every textual leaf for forbidden content.
    """
    violations = _walk(event)
    if violations:
        return IntegrationValidationResult(
            safe=False,
            violation_codes=violations,
            reason=_GENERIC_REJECT_REASON,
        )
    return IntegrationValidationResult(safe=True)


def validate_raw_payload(payload: Any) -> IntegrationValidationResult:
    """Scan the raw vendor payload before mapping for the same reasons."""
    violations = _walk(payload)
    if violations:
        return IntegrationValidationResult(
            safe=False,
            violation_codes=violations,
            reason=_GENERIC_REJECT_REASON,
        )
    return IntegrationValidationResult(safe=True)


def safe_rejection_response(result: IntegrationValidationResult) -> dict[str, Any]:
    """Public-facing rejection payload â€” never echoes the unsafe input."""
    return {
        "status": "rejected",
        "safety_status": "rejected",
        "reason": result.reason or _GENERIC_REJECT_REASON,
    }
