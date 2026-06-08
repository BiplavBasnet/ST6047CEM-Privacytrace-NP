"""Semgrep and Gitleaks JSON report parsers."""

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


def parse_scan_file(
    path: Path,
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    linked_incident_id: str | None,
) -> list[ParsedEventDraft]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Scan report must be a JSON object")

    base_ts = data.get("timestamp")
    if not base_ts:
        raise ValueError("Scan report missing top-level timestamp")
    timestamp = parse_iso_timestamp(base_ts)
    source_type = data.get("source_type") or evidence_type.value
    service_name = data.get("service_name")
    endpoint = data.get("endpoint")
    release_version = data.get("release_version")
    default_severity = map_severity(data.get("severity"))

    findings = data.get("findings")
    if not isinstance(findings, list) or not findings:
        raise ValueError("Scan report missing findings array")

    events: list[ParsedEventDraft] = []
    for idx, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            raise ValueError(f"Finding {idx} is not an object")

        rule_id = finding.get("rule_id", "unknown")
        message = finding.get("message") or data.get("message")
        raw_parts = [f"rule:{rule_id}"]
        if finding.get("path"):
            raw_parts.append(f"path:{finding['path']}")
        elif finding.get("file"):
            raw_parts.append(f"file:{finding['file']}")
        if finding.get("line"):
            raw_parts.append(f"line:{finding['line']}")

        events.append(
            ParsedEventDraft(
                event_id=build_event_id(evidence_id, idx),
                evidence_id=evidence_id,
                timestamp=timestamp,
                source_type=source_type,
                service_name=service_name,
                endpoint=endpoint,
                release_version=release_version,
                event_type=finding.get("rule_id") or "scan_finding",
                raw_reference=";".join(raw_parts),
                masked_message=message,
                severity=map_severity(finding.get("severity")) or default_severity,
                linked_incident_id=linked_incident_id,
            )
        )

    return events
