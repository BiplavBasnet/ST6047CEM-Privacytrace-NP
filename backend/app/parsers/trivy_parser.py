"""Trivy JSON report parser."""

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


def parse_trivy_file(
    path: Path,
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    linked_incident_id: str | None,
) -> list[ParsedEventDraft]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Trivy report must be a JSON object")

    base_ts = data.get("timestamp")
    if not base_ts:
        raise ValueError("Trivy report missing timestamp")
    timestamp = parse_iso_timestamp(base_ts)
    source_type = data.get("source_type") or evidence_type.value
    service_name = data.get("service_name")
    release_version = data.get("release_version")
    default_severity = map_severity(data.get("severity"))

    results = data.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy report missing results array")

    events: list[ParsedEventDraft] = []
    index = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        target = result.get("target", "unknown")
        vulnerabilities = result.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("vulnerabilities must be a list")

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            index += 1
            vuln_id = vuln.get("vulnerability_id", "unknown")
            pkg = vuln.get("pkg_name", "")
            events.append(
                ParsedEventDraft(
                    event_id=build_event_id(evidence_id, index),
                    evidence_id=evidence_id,
                    timestamp=timestamp,
                    source_type=source_type,
                    service_name=service_name,
                    endpoint=None,
                    release_version=release_version,
                    event_type="dependency_vulnerability",
                    raw_reference=f"target:{target};cve:{vuln_id};pkg:{pkg}",
                    masked_message=vuln.get("title") or data.get("message"),
                    severity=map_severity(vuln.get("severity")) or default_severity,
                    linked_incident_id=linked_incident_id,
                )
            )

    if not events:
        raise ValueError("No vulnerabilities found in Trivy report")
    return events
