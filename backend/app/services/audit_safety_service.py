"""Audit trail safety: block raw secrets and unsupported blame language."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services.llm_safety_service import load_llm_safety_rules

_MASK_TOKEN = "[MASKED]"


@dataclass
class AuditSafetyResult:
    safe: bool
    violation_codes: list[str] = field(default_factory=list)
    message: str | None = None


class AuditSafetyError(ValueError):
    """Audit payload or review comment failed safety validation."""


def _compiled_sensitive_patterns() -> list[tuple[str, re.Pattern[str]]]:
    rules = load_llm_safety_rules()
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for entry in rules.get("forbidden_input_patterns") or []:
        pattern = entry.get("pattern")
        code = entry.get("code", "forbidden_pattern")
        if pattern:
            compiled.append((code, re.compile(pattern)))
    return compiled


def _overclaim_phrases() -> list[str]:
    return list(load_llm_safety_rules().get("overclaim_phrases") or [])


def scan_text_for_sensitive(text: str) -> list[str]:
    violations: list[str] = []
    for code, pattern in _compiled_sensitive_patterns():
        if pattern.search(text):
            violations.append(code)
    return violations


def scan_text_for_overclaim(text: str) -> list[str]:
    lower = text.lower()
    found: list[str] = []
    for phrase in _overclaim_phrases():
        if phrase.lower() in lower:
            found.append(f"overclaim:{phrase}")
    return found


def mask_sensitive_text(text: str) -> str:
    masked = text
    for _code, pattern in _compiled_sensitive_patterns():
        masked = pattern.sub(_MASK_TOKEN, masked)
    return masked


def validate_review_comment(comment: str | None) -> AuditSafetyResult:
    """Reject overclaim phrases; sensitive values must be masked before storage."""
    if not comment or not comment.strip():
        return AuditSafetyResult(safe=True)
    overclaims = scan_text_for_overclaim(comment)
    if overclaims:
        return AuditSafetyResult(
            safe=False,
            violation_codes=overclaims,
            message=(
                "Review comment contains unsupported blame or overclaim language. "
                "Use likely cause, supporting evidence, and human review wording."
            ),
        )
    return AuditSafetyResult(safe=True)


def prepare_review_comment(comment: str | None) -> str | None:
    """Validate comment safety and return masked text for persistence."""
    if comment is None:
        return None
    stripped = comment.strip()
    if not stripped:
        return None
    result = validate_review_comment(stripped)
    if not result.safe:
        raise AuditSafetyError(result.message or "Unsafe review comment")
    return mask_sensitive_text(stripped)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        overclaims = scan_text_for_overclaim(value)
        if overclaims:
            raise AuditSafetyError(
                "Audit details contain unsupported blame or overclaim language."
            )
        return mask_sensitive_text(value)
    if isinstance(value, dict):
        return {k: _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


def validate_and_sanitize_audit_details(details: dict | None) -> dict:
    """Sanitize audit details before persistence; reject overclaim phrases."""
    if not details:
        return {}
    blob = json.dumps(details, default=str)
    overclaims = scan_text_for_overclaim(blob)
    if overclaims:
        raise AuditSafetyError(
            "Audit details contain unsupported blame or overclaim language."
        )
    return _sanitize_value(details)


def sanitize_audit_details_for_response(details: dict | None) -> dict:
    """Defense-in-depth sanitization when returning audit logs."""
    if not details:
        return {}
    try:
        return _sanitize_value(details)
    except AuditSafetyError:
        return {"sanitized": True, "note": "details withheld due to safety policy"}
