"""Access event JSON parser."""

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


def parse_access_file(
    path: Path,
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    linked_incident_id: str | None,
) -> list[ParsedEventDraft]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Access event must be a JSON object")

    timestamp_raw = data.get("timestamp")
    if not timestamp_raw:
        raise ValueError("Access event missing timestamp")

    actor = data.get("actor_id", "")
    resource = data.get("resource", "")
    result = data.get("result", "")

    return [
        ParsedEventDraft(
            event_id=build_event_id(evidence_id, 1),
            evidence_id=evidence_id,
            timestamp=parse_iso_timestamp(timestamp_raw),
            source_type=data.get("source_type") or evidence_type.value,
            service_name=data.get("service_name"),
            endpoint=data.get("endpoint"),
            release_version=data.get("release_version"),
            event_type=data.get("event_type") or "access_event",
            raw_reference=f"actor:{actor};resource:{resource};result:{result}",
            masked_message=data.get("message"),
            severity=map_severity(data.get("severity")),
            linked_incident_id=linked_incident_id,
        )
    ]
