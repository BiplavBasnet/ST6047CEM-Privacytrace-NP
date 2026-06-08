"""Shared types and helpers for evidence parsers (Phase 4)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.models.enums import Severity


@dataclass
class ParsedEventDraft:
    """Intermediate event before DB persistence."""

    event_id: str
    evidence_id: str
    timestamp: datetime
    source_type: str
    service_name: str | None = None
    endpoint: str | None = None
    release_version: str | None = None
    event_type: str | None = None
    raw_reference: str | None = None
    masked_message: str | None = None
    severity: Severity | None = None
    linked_incident_id: str | None = None


def build_event_id(evidence_id: str, index: int) -> str:
    return f"EVT-{evidence_id}-{index:03d}"


def parse_iso_timestamp(value: str) -> datetime:
    if not value or not isinstance(value, str):
        raise ValueError(f"Invalid timestamp: {value!r}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def map_severity(value: str | None) -> Severity | None:
    if not value:
        return None
    key = value.strip().lower()
    mapping = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "debug": Severity.LOW,
        "info": Severity.LOW,
    }
    return mapping.get(key)
