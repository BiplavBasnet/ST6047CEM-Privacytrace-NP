"""Deployment log JSON parser."""

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


def parse_deployment_file(
    path: Path,
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    linked_incident_id: str | None,
) -> list[ParsedEventDraft]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Deployment log must be a JSON object")

    timestamp_raw = data.get("timestamp")
    if not timestamp_raw:
        raise ValueError("Deployment log missing timestamp")
    timestamp = parse_iso_timestamp(timestamp_raw)
    source_type = data.get("source_type") or evidence_type.value
    severity = map_severity(data.get("severity"))

    events: list[ParsedEventDraft] = [
        ParsedEventDraft(
            event_id=build_event_id(evidence_id, 1),
            evidence_id=evidence_id,
            timestamp=timestamp,
            source_type=source_type,
            service_name=data.get("service_name"),
            endpoint=data.get("endpoint"),
            release_version=data.get("release_version"),
            event_type="deployment_completed",
            raw_reference="deployment:main",
            masked_message=data.get("message"),
            severity=severity,
            linked_incident_id=linked_incident_id,
        )
    ]

    changes = data.get("configuration_changes") or []
    if not isinstance(changes, list):
        raise ValueError("configuration_changes must be a list")

    for idx, change in enumerate(changes, start=2):
        if not isinstance(change, dict):
            raise ValueError(f"configuration_changes[{idx - 2}] is not an object")
        key = change.get("key", "unknown")
        old_val = change.get("old_value", "")
        new_val = change.get("new_value", "")
        events.append(
            ParsedEventDraft(
                event_id=build_event_id(evidence_id, idx),
                evidence_id=evidence_id,
                timestamp=timestamp,
                source_type=source_type,
                service_name=data.get("service_name"),
                endpoint=data.get("endpoint"),
                release_version=data.get("release_version"),
                event_type="configuration_change",
                raw_reference=f"config:{key}",
                masked_message=f"{key}: {old_val} -> {new_val}",
                severity=severity,
                linked_incident_id=linked_incident_id,
            )
        )

    return events
