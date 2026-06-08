"""NDJSON log parsers for api_log, runtime_log, fixed_log."""

from __future__ import annotations

import json
from pathlib import Path

from app.models.enums import EvidenceType
from app.parsers.base import (
    ParsedEventDraft,
    build_event_id,
    map_severity,
    parse_iso_timestamp,
)


def parse_log_file(
    path: Path,
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    linked_incident_id: str | None,
) -> list[ParsedEventDraft]:
    events: list[ParsedEventDraft] = []
    index = 0
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc

        index += 1
        timestamp_raw = record.get("timestamp")
        if not timestamp_raw:
            raise ValueError(f"Missing timestamp on line {line_no}")

        events.append(
            ParsedEventDraft(
                event_id=build_event_id(evidence_id, index),
                evidence_id=evidence_id,
                timestamp=parse_iso_timestamp(timestamp_raw),
                source_type=record.get("source_type") or evidence_type.value,
                service_name=record.get("service_name"),
                endpoint=record.get("endpoint"),
                release_version=record.get("release_version"),
                event_type=record.get("event_type"),
                raw_reference=f"line:{line_no}",
                masked_message=record.get("message"),
                severity=map_severity(record.get("severity")),
                linked_incident_id=linked_incident_id,
            )
        )

    if not events:
        raise ValueError("No parseable log lines found")
    return events
