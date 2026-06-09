"""Validate AI remediation output before storage or display."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.services import ai_safety_gateway

FORBIDDEN_OUTPUT_PHRASES = (
    "proven cause",
    "confirmed blame",
    "confirmed breach",
    "guaranteed fixed",
    "ai fixed the issue",
    "ai fixed the leak",
    "ai solved the incident",
    "issue solved",
    "confirmed fix",
    "confirmed bola",
    "confirmed idor",
    "attacker accessed data",
    "developer caused this",
    "developer fault",
    "incident can be closed automatically",
    "incident closed automatically",
    "send raw logs",
    "provide raw secrets",
)

REQUIRED_REMINDER = "This is a remediation suggestion only. Human review and fix verification are required."


@dataclass
class AIOutputSafetyResult:
    safe: bool
    status: str
    message: str
    violation_codes: list[str] = field(default_factory=list)


def _text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str) if not isinstance(value, str) else value


def validate_ai_output(value: dict[str, Any] | str) -> AIOutputSafetyResult:
    text = _text(value)
    lower = text.lower()
    violations = [f"forbidden_phrase_{idx}" for idx, phrase in enumerate(FORBIDDEN_OUTPUT_PHRASES, start=1) if phrase in lower]
    if ai_safety_gateway.contains_unsafe_content(text):
        violations.append("raw_sensitive_pattern")
    if violations:
        return AIOutputSafetyResult(
            safe=False,
            status="blocked_output_unsafe",
            message="AI suggestion was blocked because it contained unsafe wording or unmasked content.",
            violation_codes=violations,
        )
    return AIOutputSafetyResult(
        safe=True,
        status="safe_output",
        message="AI output passed safety validation.",
    )


def normalize_suggestion_payload(value: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                value = parsed
            else:
                value = {"suggestion_summary": value}
        except json.JSONDecodeError:
            value = {"suggestion_summary": value}

    def as_list(key: str, fallback: list[str]) -> list[str]:
        raw = value.get(key)
        if isinstance(raw, list):
            return [str(item)[:1000] for item in raw]
        if isinstance(raw, str) and raw.strip():
            return [raw.strip()[:1000]]
        return fallback

    reminder = str(value.get("human_review_reminder") or REQUIRED_REMINDER)
    limitations = as_list("limitations", [])
    if REQUIRED_REMINDER.lower() not in " ".join(limitations + [reminder]).lower():
        limitations.append(REQUIRED_REMINDER)

    return {
        "suggestion_summary": str(value.get("suggestion_summary") or value.get("plain_language_incident_summary") or "AI-generated remediation suggestion requires human review.")[:4000],
        "likely_issue_area": str(value.get("likely_issue_area") or "logging_or_redaction_review")[:255],
        "remediation_actions": as_list("remediation_actions", ["Review logging and redaction controls for the affected service."]),
        "code_or_config_areas": as_list("code_or_config_areas", ["Logging middleware", "Redaction configuration", "Sensitive endpoint handlers"]),
        "suggested_tests": as_list("suggested_tests", ["Run retest evidence through detection after remediation."]),
        "retest_evidence_required": as_list("retest_evidence_required", ["Masked retest logs or scans showing whether sensitive values still appear."]),
        "limitations": limitations,
    }


def validate_reviewer_text(value: Any) -> AIOutputSafetyResult:
    return validate_ai_output({"reviewer_content": value})
