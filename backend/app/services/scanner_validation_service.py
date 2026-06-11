"""Validate normalised scanner finding drafts before persistence.

Scanner findings are INGESTED evidence: this module only rejects raw
sensitive values that cannot be safely masked. It does NOT reject findings
for certainty/blame wording (e.g. "proven cause") in fields like
`explanation`, since that text may legitimately quote the external
scanner's own finding description. See
docs/INPUT_OUTPUT_SAFETY_SEPARATION.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services import scanner_safety_service

_GENERIC_REASON = (
    "Finding contains an unsafe raw sensitive value that cannot be safely masked. "
    "Send masked values only."
)


@dataclass
class ScannerValidationResult:
    safe: bool
    violation_codes: list[str] = field(default_factory=list)
    reason: str | None = None


def audit_safe_violation_codes(codes: list[str]) -> list[str]:
    safe: list[str] = []
    for code in codes:
        if code.startswith("overclaim:"):
            safe.append("overclaim_phrase")
        else:
            safe.append(code)
    return list(dict.fromkeys(safe))


def validate_finding_dict(finding: dict[str, Any]) -> ScannerValidationResult:
    blob_parts: list[str] = []
    for key in ("masked_value", "explanation", "source_file", "detector_name"):
        val = finding.get(key)
        if isinstance(val, str) and val:
            blob_parts.append(val)
    text = " ".join(blob_parts)
    violations = scanner_safety_service._violation_codes_for_text(text)
    masked_value = finding.get("masked_value")
    if (
        violations
        and set(violations) == {"api_key_raw"}
        and isinstance(masked_value, str)
        and "*" in masked_value
    ):
        violations = []
    if violations:
        return ScannerValidationResult(
            safe=False,
            violation_codes=audit_safe_violation_codes(violations),
            reason=_GENERIC_REASON,
        )
    return ScannerValidationResult(safe=True)
