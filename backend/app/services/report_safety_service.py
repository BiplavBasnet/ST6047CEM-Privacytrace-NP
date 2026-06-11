"""Safety validation and sanitization for incident and final investigation reports."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services import audit_safety_service
from app.services.scanner_safety_service import remask_string

BLOCKED_OVERCLAIM_EXTRA = (
    "guaranteed fixed",
    "definitely fixed",
    "proven fixed",
    "incident closed automatically",
)

FORBIDDEN_OVERCLAIM_REPLACEMENTS = {
    "proven cause": "likely cause",
    "confirmed blame": "supporting evidence suggests",
    "guaranteed cause": "likely cause",
    "definitely caused by": "may indicate",
    "developer fault": "requires verification",
    "guaranteed fixed": "requires verification",
    "incident closed automatically": "human review required",
    "confirmed breach": "privacy incident under review",
    "attacker accessed data": "access requires further evidence",
}

FORBIDDEN_EXPORT_KEYS = frozenset(
    {
        "raw",
        "Raw",
        "raw_value",
        "raw_payload",
        "raw_reference",
        "secret",
        "Secret",
        "full_token",
        "private_key",
        "password",
        "password_hash",
        "plaintext_password",
        "session_token",
        "authorization",
        "Authorization",
        "decrypted_payload",
    }
)

_OMITTED_WARNING = "unsafe raw value omitted"


@dataclass
class ReportSafetyResult:
    safe: bool
    violation_codes: list[str] = field(default_factory=list)
    message: str | None = None


@dataclass
class ExportSanitizeResult:
    value: Any
    warnings: list[str] = field(default_factory=list)


class ReportSafetyError(ValueError):
    """Report or metrics payload failed privacy/safety validation."""


def validate_text_blob(text: str) -> ReportSafetyResult:
    violations: list[str] = []
    violations.extend(audit_safety_service.scan_text_for_sensitive(text))
    violations.extend(audit_safety_service.scan_text_for_overclaim(text))
    lower = text.lower()
    for phrase in BLOCKED_OVERCLAIM_EXTRA:
        if phrase in lower:
            violations.append(f"overclaim:{phrase}")
    if violations:
        return ReportSafetyResult(
            safe=False,
            violation_codes=violations,
            message=(
                "Report or metrics output failed safety validation. "
                "Raw sensitive values and unsupported certainty phrases are not allowed."
            ),
        )
    return ReportSafetyResult(safe=True)


def validate_report_payload(payload: dict) -> ReportSafetyResult:
    blob = json.dumps(payload, default=str)
    return validate_text_blob(blob)


def assert_report_safe(payload: dict) -> None:
    result = validate_report_payload(payload)
    if not result.safe:
        raise ReportSafetyError(result.message or "Unsafe report content")


def validate_html_document(html: str) -> ReportSafetyResult:
    return validate_text_blob(html)


def replace_overclaim_phrases(text: str) -> str:
    if not text:
        return text
    result = text
    lower = result.lower()
    for phrase, replacement in FORBIDDEN_OVERCLAIM_REPLACEMENTS.items():
        if phrase in lower:
            result = re.sub(re.escape(phrase), replacement, result, flags=re.IGNORECASE)
    return result


def sanitize_export_text(text: str | None) -> ExportSanitizeResult:
    """Mask or omit unsafe text for final report export."""
    warnings: list[str] = []
    if text is None:
        return ExportSanitizeResult(value=None, warnings=warnings)
    if not str(text).strip():
        return ExportSanitizeResult(value="", warnings=warnings)

    raw = str(text)
    masked, remaining = remask_string(raw)
    if remaining:
        warnings.append(_OMITTED_WARNING)
        if audit_safety_service.scan_text_for_sensitive(masked):
            return ExportSanitizeResult(value=None, warnings=warnings)

    safe = replace_overclaim_phrases(masked)
    if audit_safety_service.scan_text_for_overclaim(safe):
        safe = replace_overclaim_phrases(safe)
        warnings.append("overclaim phrase replaced with safe wording")

    post_check = audit_safety_service.scan_text_for_sensitive(safe)
    if post_check:
        warnings.append(_OMITTED_WARNING)
        return ExportSanitizeResult(value=None, warnings=warnings)

    return ExportSanitizeResult(value=safe, warnings=warnings)


def _sanitize_export_value(value: Any, *, key: str | None = None) -> ExportSanitizeResult:
    if key in FORBIDDEN_EXPORT_KEYS:
        return ExportSanitizeResult(value=None, warnings=[_OMITTED_WARNING])

    if value is None:
        return ExportSanitizeResult(value=None, warnings=[])
    if isinstance(value, bool):
        return ExportSanitizeResult(value=value, warnings=[])
    if isinstance(value, (int, float)):
        return ExportSanitizeResult(value=value, warnings=[])
    if isinstance(value, str):
        return sanitize_export_text(value)
    if isinstance(value, list):
        out_list: list[Any] = []
        warnings: list[str] = []
        for item in value:
            cleaned = _sanitize_export_value(item)
            warnings.extend(cleaned.warnings)
            if cleaned.value is not None:
                out_list.append(cleaned.value)
        return ExportSanitizeResult(value=out_list, warnings=warnings)
    if isinstance(value, dict):
        out_dict: dict[str, Any] = {}
        warnings: list[str] = []
        for k, v in value.items():
            if k in FORBIDDEN_EXPORT_KEYS:
                warnings.append(_OMITTED_WARNING)
                continue
            cleaned = _sanitize_export_value(v, key=k)
            warnings.extend(cleaned.warnings)
            if cleaned.value is not None:
                out_dict[k] = cleaned.value
        return ExportSanitizeResult(value=out_dict, warnings=warnings)
    return sanitize_export_text(str(value))


def sanitize_final_report_dict(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Deep-sanitize a final report structure before serialization."""
    cleaned = _sanitize_export_value(payload)
    report = cleaned.value if isinstance(cleaned.value, dict) else {}
    warnings = list(dict.fromkeys(cleaned.warnings))
    result = validate_report_payload(report)
    if not result.safe:
        raise ReportSafetyError(result.message or "Unsafe final report after sanitization")
    return report, warnings


def safety_warning_message(codes: list[str]) -> str:
    """Build a safe warning without echoing sensitive values."""
    if not codes:
        return ""
    generic = list(dict.fromkeys(codes))
    return f"Safety controls applied: {', '.join(generic[:8])}"
