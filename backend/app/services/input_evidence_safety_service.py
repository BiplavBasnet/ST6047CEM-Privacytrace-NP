"""Input evidence safety: size, schema, and sensitive-value masking for
INGESTED evidence (scanner findings, SIEM/SOC integration events,
live-monitor events, uploaded evidence files, and other third-party
payloads).

Separation contract (see docs/INPUT_OUTPUT_SAFETY_SEPARATION.md):

* INPUT evidence is text/data PrivacyTrace-NP did not generate. It may
  legitimately quote or paraphrase alarming language from the source
  system (e.g. a SOC analyst's ticket that reads "attacker accessed
  data", or a scanner tool's own finding description that says
  "confirmed breach"). Rejecting ingestion because of that wording would
  mean PrivacyTrace refuses to record what the source system actually
  reported. This module therefore NEVER rejects input for wording/
  narrative content alone. It only:

    1. Enforces size limits — oversized text fields or structured
       payloads are rejected (resource-exhaustion / DoS defence).
    2. Enforces basic schema sanity — payloads must be JSON-serialisable
       with bounded nesting depth and key count.
    3. Detects and masks raw secrets/sensitive identifiers that must
       never be stored or echoed unmasked (passwords, API keys, JWTs,
       private keys, Nepal phone numbers, wallet/transaction IDs, etc.),
       rejecting only when a value cannot be safely masked.

* OUTPUT claim safety is a *different* concern handled elsewhere:
  `report_safety_service`, `ai_output_safety_service`, and
  `llm_safety_service.validate_investigation_output` block
  PrivacyTrace's own generated conclusions from asserting unsupported
  certainty ("confirmed breach", "proven cause", ...). Those modules are
  unrelated to this one and are not affected by it.

This module reuses the hard-secret detection/masking already implemented
in `scanner_safety_service` (the canonical INPUT secret scanner) rather
than duplicating the regex bank, so there is a single source of truth for
"what counts as a raw secret that must be masked".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.services import audit_safety_service, scanner_safety_service

MAX_TEXT_FIELD_LENGTH = 20_000
MAX_PAYLOAD_SERIALIZED_BYTES = 512_000
MAX_PAYLOAD_DEPTH = 12
MAX_PAYLOAD_KEYS = 2_000

SIZE_REJECT_REASON = "Ingested evidence exceeds the configured size limit."
SCHEMA_REJECT_REASON = "Ingested evidence has an invalid or unsafe structure."
SECRET_REJECT_REASON = (
    "Ingested evidence contains raw sensitive values that cannot be safely masked. "
    "Provide masked or redacted values only."
)


@dataclass
class InputEvidenceSafetyResult:
    safe: bool
    sanitized_value: Any = None
    violation_codes: list[str] = field(default_factory=list)
    reason: str | None = None


def _depth(value: Any, current: int = 0) -> int:
    if current > MAX_PAYLOAD_DEPTH:
        return current
    if isinstance(value, dict):
        if not value:
            return current
        return max(_depth(v, current + 1) for v in value.values())
    if isinstance(value, (list, tuple)):
        if not value:
            return current
        return max(_depth(v, current + 1) for v in value)
    return current


def _key_count(value: Any) -> int:
    count = 0
    if isinstance(value, dict):
        count += len(value)
        for v in value.values():
            count += _key_count(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            count += _key_count(v)
    return count


def validate_input_text(
    text: str | None,
    *,
    field_name: str = "text",
    max_length: int = MAX_TEXT_FIELD_LENGTH,
) -> InputEvidenceSafetyResult:
    """Validate and mask a single piece of ingested free text.

    Never rejects for narrative wording, certainty phrases, or blame
    language — only for oversized input, malformed encoding, or raw
    secrets that cannot be safely masked.
    """
    if text is None:
        return InputEvidenceSafetyResult(safe=True, sanitized_value=None)
    if not isinstance(text, str):
        text = str(text)

    if len(text) > max_length:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=[f"{field_name}_too_large"],
            reason=SIZE_REJECT_REASON,
        )
    if "\x00" in text:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=[f"{field_name}_malformed"],
            reason=SCHEMA_REJECT_REASON,
        )

    masked, remaining = scanner_safety_service.remask_string(text)
    if remaining:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=list(remaining),
            reason=SECRET_REJECT_REASON,
        )
    return InputEvidenceSafetyResult(safe=True, sanitized_value=masked)


def validate_input_payload(
    payload: Any,
    *,
    max_bytes: int = MAX_PAYLOAD_SERIALIZED_BYTES,
    max_depth: int = MAX_PAYLOAD_DEPTH,
    max_keys: int = MAX_PAYLOAD_KEYS,
) -> InputEvidenceSafetyResult:
    """Validate and mask a structured (dict/list/scalar) ingested payload.

    Rejects only for size/schema limits or unmaskable raw secrets — never
    for narrative wording inside string leaves.
    """
    try:
        blob = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=["not_json_serializable"],
            reason=SCHEMA_REJECT_REASON,
        )

    if len(blob.encode("utf-8")) > max_bytes:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=["payload_too_large"],
            reason=SIZE_REJECT_REASON,
        )
    if _depth(payload) > max_depth:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=["payload_too_deep"],
            reason=SCHEMA_REJECT_REASON,
        )
    if _key_count(payload) > max_keys:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=["payload_too_many_keys"],
            reason=SCHEMA_REJECT_REASON,
        )

    result = scanner_safety_service.sanitize_payload(payload)
    if not result.safe:
        return InputEvidenceSafetyResult(
            safe=False,
            violation_codes=result.violation_codes,
            reason=result.reason or SECRET_REJECT_REASON,
        )
    return InputEvidenceSafetyResult(
        safe=True,
        sanitized_value=result.sanitised_payload,
        violation_codes=result.violation_codes,
    )


def contains_overclaim_wording(text: str) -> bool:
    """Diagnostic helper only — NEVER used to reject or drop input.

    Exposed so callers may optionally *flag* narrative certainty wording
    for human review (e.g. surfacing "this quote uses certainty
    language" in an analyst UI) without blocking ingestion of the
    underlying evidence.
    """
    if not text:
        return False
    return bool(audit_safety_service.scan_text_for_overclaim(text))
