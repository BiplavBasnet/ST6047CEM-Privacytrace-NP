"""Map adapter drafts to canonical scanner evidence field sets."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from app.models.enums import Severity

_DEFAULT_EXPLANATION = (
    "External scanner finding may indicate related credential exposure risk; "
    "requires human review and supports investigation as supporting evidence only."
)


def _map_severity(value: str | None) -> Severity | None:
    if not value:
        return None
    v = str(value).lower()
    if v in ("critical", "error"):
        return Severity.CRITICAL
    if v in ("high", "warning"):
        return Severity.HIGH
    if v in ("medium", "note"):
        return Severity.MEDIUM
    if v in ("low", "info"):
        return Severity.LOW
    return Severity.MEDIUM


def _clamp01(value: float | None, default: float = 0.5) -> float:
    if value is None:
        return default
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, v))


def _safe_explanation(text: str | None) -> str:
    """Pass through the scanner's own explanation text (input evidence).

    Certainty/blame wording (e.g. "proven cause") is NOT filtered here: the
    explanation may legitimately quote the external scanner's own finding
    description. Raw secrets are still caught downstream by
    `scanner_validation_service` / `input_evidence_safety_service` before
    persistence. See docs/INPUT_OUTPUT_SAFETY_SEPARATION.md.
    """
    if not text or not str(text).strip():
        return _DEFAULT_EXPLANATION
    return str(text)[:2000]


def finding_fingerprint(
    *,
    source_format: str,
    detector_name: str | None,
    source_file: str | None,
    line_number: int | None,
    masked_value: str | None,
) -> str:
    blob = "|".join(
        [
            source_format,
            detector_name or "",
            source_file or "",
            str(line_number or ""),
            masked_value or "",
        ]
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def map_draft_to_record_fields(
    draft: dict[str, Any],
    *,
    source_format: str,
    raw_payload_hash: str,
    import_evidence_id: str,
    linked_incident_id: str | None,
    service_hint: str | None,
    endpoint_hint: str | None,
    release_version_hint: str | None,
) -> dict[str, Any]:
    scanner_evidence_id = f"SCN-{uuid.uuid4().hex[:12].upper()}"
    detector = draft.get("detector_name")
    masked = draft.get("masked_value")
    if isinstance(masked, str) and masked.strip():
        masked_str = masked.strip()[:512]
    else:
        masked_str = None

    line = draft.get("line_number")
    if line is not None:
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = None

    fp = finding_fingerprint(
        source_format=source_format,
        detector_name=str(detector) if detector else None,
        source_file=draft.get("source_file"),
        line_number=line,
        masked_value=masked_str,
    )
    evidence_ref = draft.get("evidence_reference") or f"SCN-REF-{fp[:12].upper()}"

    return {
        "scanner_evidence_id": scanner_evidence_id,
        "import_evidence_id": import_evidence_id,
        "source_format": source_format,
        "scanner_category": draft.get("scanner_category") or "external_scanner",
        "finding_type": draft.get("finding_type") or "secret_exposure",
        "detector_name": str(detector)[:256] if detector else None,
        "verification_status": draft.get("verification_status") or "unknown",
        "severity": _map_severity(draft.get("severity")),
        "confidence": _clamp01(draft.get("confidence"), 0.6),
        "causal_relevance_score": None,
        "repository": (str(draft["repository"])[:512] if draft.get("repository") else None),
        "source_file": (str(draft["source_file"])[:1024] if draft.get("source_file") else None),
        "line_number": line,
        "commit_id": (str(draft["commit_id"])[:128] if draft.get("commit_id") else None),
        "branch": (str(draft["branch"])[:256] if draft.get("branch") else None),
        "masked_value": masked_str,
        "evidence_reference": evidence_ref[:255],
        "linked_evidence_id": import_evidence_id,
        "linked_incident_id": linked_incident_id,
        "service_hint": service_hint,
        "endpoint_hint": endpoint_hint,
        "release_version_hint": release_version_hint,
        "detected_at": draft.get("detected_at"),
        "imported_at": datetime.now(UTC),
        "safety_status": "safe",
        "raw_payload_hash": raw_payload_hash,
        "tags": draft.get("tags") if isinstance(draft.get("tags"), list) else [],
        "explanation": _safe_explanation(draft.get("explanation")),
        "finding_fingerprint": fp,
    }
