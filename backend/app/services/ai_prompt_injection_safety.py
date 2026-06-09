"""Prompt-injection safety for untrusted evidence text in AI remediation context."""

from __future__ import annotations

import re
from typing import Any

from app.services import remediation_ai_safety_service, report_safety_service, restricted_data_policy_service

_SUSPICIOUS_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|system)\s+(rules?|instructions?)", re.I),
    re.compile(r"you\s+are\s+now\s+(?:a|an|the)\b", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\s*/?\s*system\s*>", re.I),
    re.compile(r"do\s+not\s+follow\s+(?:your|the)\s+(?:safety|policy)", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"override\s+(?:safety|policy|guardrails?)", re.I),
]


def detect_suspicious_instruction_text(text: str | None) -> bool:
    if not text or not str(text).strip():
        return False
    sample = str(text)
    return any(pat.search(sample) for pat in _SUSPICIOUS_PATTERNS)


def wrap_untrusted_evidence(label: str, value: Any) -> str:
    """Wrap untrusted content so model prompts treat it as data, not instructions."""
    text = "" if value is None else str(value)
    text = re.sub(r"\[\s*/?\s*UNTRUSTED_EVIDENCE\b", "[UNTRUSTED_DATA", text, flags=re.I)
    flagged = detect_suspicious_instruction_text(text)
    safe_label = re.sub(r"[^A-Za-z0-9_.\[\]-]", "_", label)[:160]
    header = f"[UNTRUSTED_EVIDENCE label={safe_label}"
    if flagged:
        header += " suspicious_instruction=true"
    header += "]"
    return f"{header}\n{text}\n[/UNTRUSTED_EVIDENCE]"


def sanitize_package_strings(package: dict[str, Any]) -> dict[str, Any]:
    """Shallow-wrap common free-text package fields used in diagnosis prompts."""
    out = dict(package)
    for key in ("problem_narrative", "summary", "likely_root_cause_explanation"):
        if key in out and out[key]:
            out[key] = wrap_untrusted_evidence(key, out[key])
    return out


_OMIT_KEYS = frozenset(
    {
        "raw",
        "raw_value",
        "raw_payload",
        "authorization",
        "password",
        "secret",
        "correlation_identifiers",
        "trace_id",
        "request_id",
        "correlation_id",
    }
)


def build_untrusted_provider_context(
    package: dict[str, Any],
    *,
    localisation: dict[str, Any],
    code_context: dict[str, Any],
) -> dict[str, Any]:
    """Recursively minimise and delimit every external-provider string as data."""

    def clean(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            return {
                f"field_{index}": {
                    "name": re.sub(r"[^A-Za-z0-9_.-]", "_", str(key))[:80],
                    "value": cleaned,
                }
                for index, (key, item) in enumerate(value.items())
                if str(key).lower() not in _OMIT_KEYS
                and (cleaned := clean(item, f"{path}.{key}")) is not None
            }
        if isinstance(value, list):
            return [cleaned for index, item in enumerate(value[:20]) if (cleaned := clean(item, f"{path}[{index}]")) is not None]
        if isinstance(value, str):
            safe = report_safety_service.sanitize_export_text(value).value
            return wrap_untrusted_evidence(path, safe) if safe else None
        return value

    combined = {
        "evidence": package,
        "source_claim": {
            key: localisation.get(key)
            for key in (
                "exact_source_location_known",
                "file_path",
                "function_or_class",
                "configuration_section",
                "line_range",
                "evidence_references",
                "likely_component",
            )
        },
        "source_code": code_context if code_context.get("context_available") else None,
    }
    filtered, _ = restricted_data_policy_service.sanitize_payload(combined, channel="external_ai")
    result = clean(filtered, "provider_context")
    remediation_ai_safety_service.assert_no_raw_sensitive(result)
    return result
