"""Privacy alert persistence helpers for Live Privacy Monitor."""

from __future__ import annotations

import uuid
from datetime import datetime, UTC
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import Severity
from app.models.privacy_alert import PrivacyAlert
from app.schemas.live_monitor_schema import LiveAlertRead
from app.services import live_alert_grouping_service


def generate_alert_id() -> str:
    return f"LPA-{uuid.uuid4().hex[:12].upper()}"


def normalize_severity(value: str | Severity | None) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity((value or "medium").lower())
    except ValueError:
        return Severity.MEDIUM


def create_alert(
    db: Session,
    *,
    alert_time: datetime | None,
    source_type: str,
    source_name: str | None,
    source_format: str,
    service_name: str | None,
    endpoint: str | None,
    environment: str | None,
    severity: Severity,
    sensitive_types: Iterable[str],
    masked_values: Iterable[str],
    raw_event_hash: str,
    alert_summary: str,
    alert_group_key: str | None = None,
    exposure_location: str | None = None,
    confidence_score: float | None = None,
    confidence_level: str | None = None,
    alert_findings: list[dict[str, Any]] | None = None,
    correlation_keys: dict[str, Any] | None = None,
    trace_fingerprint: str | None = None,
    observed_at: datetime | None = None,
    source_time_quality: str = "inferred",
    source_time_inferred: bool = True,
    source_timezone_name: str | None = None,
) -> PrivacyAlert:
    now = datetime.now(UTC)
    resolved_alert_time = alert_time or now
    received_time = observed_at or now
    alert = PrivacyAlert(
        alert_id=generate_alert_id(),
        alert_time=resolved_alert_time,
        received_at=received_time,
        source_type=source_type,
        source_name=source_name,
        source_format=source_format,
        service_name=service_name,
        endpoint=endpoint,
        environment=environment,
        severity=severity,
        status="new",
        sensitive_types=list(dict.fromkeys(sensitive_types)),
        masked_values=list(dict.fromkeys(masked_values)),
        detection_ids=[],
        raw_event_hash=raw_event_hash,
        safety_status="safe",
        alert_summary=alert_summary,
        human_review_required=True,
        alert_group_key=alert_group_key,
        first_seen=received_time,
        last_seen=received_time,
        first_source_event_time=alert_time,
        last_source_event_time=alert_time,
        source_time_quality=source_time_quality,
        source_time_inferred=source_time_inferred,
        source_timezone_name=source_timezone_name,
        repeat_count=1,
        # Distinct known traces only — 0 until a real trace_id is recorded.
        affected_trace_count=None,
        trace_count_quality="unavailable",
        grouping_rule_version=live_alert_grouping_service.GROUPING_RULE_VERSION if alert_group_key else None,
        exposure_location=exposure_location,
        confidence_score=confidence_score,
        confidence_level=confidence_level,
        alert_findings=alert_findings or [],
        correlation_keys=correlation_keys or None,
    )
    db.add(alert)
    db.flush()
    live_alert_grouping_service.record_trace_reference(
        db,
        alert,
        trace_fingerprint=trace_fingerprint or (correlation_keys or {}).get("trace_id_fingerprint"),
        at=received_time,
    )
    return alert


def alert_to_read(alert: PrivacyAlert) -> LiveAlertRead:
    return LiveAlertRead(
        alert_id=alert.alert_id,
        alert_time=alert.alert_time,
        received_at=alert.received_at,
        source_type=alert.source_type,
        source_name=alert.source_name,
        source_format=alert.source_format,
        service_name=alert.service_name,
        endpoint=alert.endpoint,
        environment=alert.environment,
        severity=alert.severity.value if alert.severity else "medium",
        status=alert.status,
        sensitive_types=[str(x) for x in (alert.sensitive_types or [])],
        masked_values=[str(x) for x in (alert.masked_values or [])],
        detection_ids=[str(x) for x in (alert.detection_ids or [])],
        evidence_id=alert.evidence_id,
        linked_incident_id=alert.linked_incident_id,
        raw_event_hash=alert.raw_event_hash,
        safety_status=alert.safety_status,
        alert_summary=alert.alert_summary,
        human_review_required=alert.human_review_required,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        first_seen=alert.first_seen or alert.alert_time,
        last_seen=alert.last_seen or alert.alert_time,
        repeat_count=alert.repeat_count or 1,
        ingestion_source=alert.ingestion_source or "live_monitor",
        missing_metadata=[str(x) for x in (alert.missing_metadata or [])],
        correlation_recommendations=[
            str(x) for x in (alert.correlation_recommendations or [])
        ],
        evidence_strength=alert.evidence_strength or "limited",
        alert_group_key=alert.alert_group_key,
        affected_trace_count=alert.affected_trace_count,
        trace_count_quality=alert.trace_count_quality or "unavailable",
        first_source_event_time=alert.first_source_event_time,
        last_source_event_time=alert.last_source_event_time,
        source_time_quality=alert.source_time_quality or "inferred",
        source_time_inferred=alert.source_time_inferred,
        source_timezone_name=alert.source_timezone_name,
        grouping_rule_version=alert.grouping_rule_version,
        exposure_location=alert.exposure_location,
        confidence_score=alert.confidence_score,
        confidence_level=alert.confidence_level,
    )


def get_alert(db: Session, alert_id: str) -> PrivacyAlert | None:
    return db.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id))


def list_alerts(
    db: Session,
    *,
    status: str | None = None,
    severity: str | None = None,
    source_name: str | None = None,
    linked_incident_id: str | None = None,
    limit: int = 50,
) -> list[PrivacyAlert]:
    stmt = select(PrivacyAlert)
    if status:
        stmt = stmt.where(PrivacyAlert.status == status)
    if severity:
        stmt = stmt.where(PrivacyAlert.severity == normalize_severity(severity))
    if source_name:
        stmt = stmt.where(PrivacyAlert.source_name == source_name)
    if linked_incident_id:
        stmt = stmt.where(PrivacyAlert.linked_incident_id == linked_incident_id)
    stmt = stmt.order_by(PrivacyAlert.alert_time.desc(), PrivacyAlert.id.desc()).limit(max(1, min(limit, 200)))
    return list(db.scalars(stmt).all())
