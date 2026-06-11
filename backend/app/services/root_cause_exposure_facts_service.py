"""Structured exposure facts for root-cause scoring (Phase L).

Converts already-persisted, safe (no-raw-value) exposure evidence —
`PrivacyAlert.alert_findings`, `Detection` (+ its `NormalizedEvent`), and raw
`sensitive_exposure_engine.analyse()` finding dicts — into a small, uniform
`ExposureFact` shape:

    sensitive_type, exposure_location, field_name, service, endpoint,
    environment, confidence, exposure_decision, deployment_version, trace_id

`causality_engine.py` folds these into `EvidenceContext.exposure_facts` and
uses them (a) as an optional signal source for `root_cause_rules.yaml`
(`exposure_fact_type_at_location` match type) and (b) to evaluate ontology
category boosts (`root_cause_ontology_service`). No raw sensitive value is
ever read or stored here — only fields already present on masked/aggregated
rows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection import Detection
from app.models.normalized_event import NormalizedEvent
from app.models.privacy_alert import PrivacyAlert
from app.services import sensitive_exposure_engine as exposure_engine

FACT_SOURCE_ALERT_FINDING = "alert_finding"
FACT_SOURCE_DETECTION = "detection"
FACT_SOURCE_EXPOSURE_FINDING = "exposure_finding"


def _safe_time(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


@dataclass(frozen=True)
class ExposureFact:
    """A single structured, pre-remediation exposure observation.

    Deliberately mirrors the field set requested by the brief: no raw value,
    no remediation/review/verification state — only what was technically
    observed about *where* and *what kind* of sensitive data appeared.
    """

    fact_id: str
    source: str
    evidence_id: str | None
    sensitive_type: str | None
    exposure_location: str | None
    field_name: str | None
    service: str | None
    endpoint: str | None
    environment: str | None
    confidence: float | None
    exposure_decision: str | None
    deployment_version: str | None
    trace_id: str | None
    event_time: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "source": self.source,
            "evidence_id": self.evidence_id,
            "sensitive_type": self.sensitive_type,
            "exposure_location": self.exposure_location,
            "field_name": self.field_name,
            "service": self.service,
            "endpoint": self.endpoint,
            "environment": self.environment,
            "confidence": self.confidence,
            "exposure_decision": self.exposure_decision,
            "deployment_version": self.deployment_version,
            "trace_id": self.trace_id,
            "event_time": self.event_time,
        }


def facts_from_alert(alert: Any) -> list[ExposureFact]:
    """Build facts from `PrivacyAlert.alert_findings` (safe per-finding snapshot)."""
    facts: list[ExposureFact] = []
    findings = getattr(alert, "alert_findings", None) or []
    alert_id = getattr(alert, "alert_id", "unknown")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        facts.append(
            ExposureFact(
                fact_id=f"ALERTFACT-{alert_id}-{index}",
                source=FACT_SOURCE_ALERT_FINDING,
                evidence_id=getattr(alert, "evidence_id", None),
                sensitive_type=finding.get("sensitive_type"),
                exposure_location=(
                    finding.get("exposure_location") or getattr(alert, "exposure_location", None)
                ),
                field_name=finding.get("field_name_safe") or finding.get("field_name"),
                service=finding.get("service_name") or getattr(alert, "service_name", None),
                endpoint=finding.get("endpoint") or getattr(alert, "endpoint", None),
                environment=finding.get("environment") or getattr(alert, "environment", None),
                confidence=finding.get("confidence_score"),
                exposure_decision=finding.get("exposure_decision"),
                deployment_version=finding.get("deployment_version"),
                trace_id=finding.get("trace_id"),
                event_time=_safe_time(getattr(alert, "alert_time", None)),
            )
        )
    return facts


def fact_from_detection(detection: Any, event: Any | None = None) -> ExposureFact:
    """Build a fact from a `Detection`, enriched with its `NormalizedEvent` if known."""
    exposure_location: str | None = None
    deployment_version: str | None = None
    trace_id: str | None = None
    service: str | None = None
    endpoint: str | None = None
    event_time: str | None = None
    if event is not None:
        exposure_location = exposure_engine.source_type_to_exposure_location(
            getattr(event, "source_type", None)
        )
        deployment_version = getattr(event, "deployment_version", None)
        trace_id = getattr(event, "trace_id", None)
        service = getattr(event, "service_name", None)
        endpoint = getattr(event, "endpoint", None)
        event_time = _safe_time(getattr(event, "timestamp", None))
    return ExposureFact(
        fact_id=f"DETFACT-{getattr(detection, 'detection_id', 'unknown')}",
        source=FACT_SOURCE_DETECTION,
        evidence_id=getattr(detection, "evidence_id", None),
        sensitive_type=getattr(detection, "sensitive_type", None),
        exposure_location=exposure_location,
        field_name=None,
        service=service,
        endpoint=endpoint,
        environment=None,
        confidence=getattr(detection, "confidence", None),
        exposure_decision=None,
        deployment_version=deployment_version,
        trace_id=trace_id,
        event_time=event_time,
    )


def fact_from_finding(finding: dict, *, evidence_id: str | None = None) -> ExposureFact:
    """Build a fact directly from a `sensitive_exposure_engine.analyse()` finding dict."""
    return ExposureFact(
        fact_id=str(finding.get("finding_id") or f"FINDINGFACT-{id(finding)}"),
        source=FACT_SOURCE_EXPOSURE_FINDING,
        evidence_id=evidence_id,
        sensitive_type=finding.get("sensitive_type"),
        exposure_location=finding.get("exposure_location"),
        field_name=finding.get("field_name_safe"),
        service=finding.get("service_name"),
        endpoint=finding.get("endpoint"),
        environment=finding.get("environment"),
        confidence=finding.get("confidence_score"),
        exposure_decision=finding.get("exposure_decision"),
        deployment_version=None,
        trace_id=None,
        event_time=_safe_time(finding.get("event_time")),
    )


def build_exposure_facts_from_records(
    *,
    alerts: list[Any] | None = None,
    detections: list[Any] | None = None,
    events_by_id: dict[str, Any] | None = None,
    findings: list[dict] | None = None,
) -> list[ExposureFact]:
    """Pure aggregation over already-fetched rows — no database access.

    Kept separate from `build_exposure_facts` so tests (and future callers
    that already hold the rows in memory) never need a live database.
    """
    events_by_id = events_by_id or {}
    facts: list[ExposureFact] = []
    for alert in alerts or []:
        facts.extend(facts_from_alert(alert))
    for detection in detections or []:
        event = events_by_id.get(getattr(detection, "normalized_event_id", None))
        facts.append(fact_from_detection(detection, event))
    for finding in findings or []:
        facts.append(fact_from_finding(finding))
    return facts


def build_exposure_facts(db: Session, incident_id: str) -> list[ExposureFact]:
    """Fetch and convert all exposure facts durably linked to an incident."""
    alerts = list(
        db.scalars(
            select(PrivacyAlert).where(PrivacyAlert.linked_incident_id == incident_id)
        ).all()
    )
    detections = list(
        db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    )
    event_ids = {d.normalized_event_id for d in detections if d.normalized_event_id}
    events_by_id: dict[str, Any] = {}
    if event_ids:
        events = list(
            db.scalars(
                select(NormalizedEvent).where(NormalizedEvent.event_id.in_(event_ids))
            ).all()
        )
        events_by_id = {e.event_id: e for e in events}
    return build_exposure_facts_from_records(
        alerts=alerts, detections=detections, events_by_id=events_by_id
    )


def index_facts_by_type_and_location(
    facts: list[ExposureFact],
) -> dict[tuple[str, str], list[ExposureFact]]:
    """Group facts by `(sensitive_type, exposure_location)` for quick lookups."""
    index: dict[tuple[str, str], list[ExposureFact]] = {}
    for fact in facts:
        if not fact.sensitive_type or not fact.exposure_location:
            continue
        key = (fact.sensitive_type, fact.exposure_location)
        index.setdefault(key, []).append(fact)
    return index
