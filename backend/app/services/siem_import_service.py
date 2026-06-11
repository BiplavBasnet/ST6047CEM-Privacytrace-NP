"""Privacy-safe ingestion pipeline for the Universal Integration Gateway."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import EvidenceType, ParsingStatus
from app.models.evidence_file import EvidenceFile
from app.models.integration_event import IntegrationEvent
from app.models.normalized_event import NormalizedEvent
from app.schemas.integration_schema import (
    ACCEPTED_SOURCE_TYPES,
    INTEGRATION_SCHEMA_VERSION,
    IntegrationEventIngestRequest,
    IntegrationEventSafeRead,
)
from app.schemas.live_monitor_schema import LiveMonitorEventRequest
from app.services import (
    audit_service,
    correlation_fingerprint_service,
    integration_mapping_service,
    live_alert_service,
    live_ingestion_adapter_service,
    live_monitor_safety_service,
    live_monitor_service,
)


@dataclass
class IngestionOutcome:
    status: str
    safety_status: str
    integration_event_id: str | None
    canonical: dict[str, Any] | None
    reason: str | None
    violation_codes: list[str]
    evidence_id: str | None
    alert_created: bool = False
    alert_id: str | None = None
    missing_metadata: list[str] | None = None
    recommendations: list[str] | None = None


@dataclass
class PreparedIntegrationEvent:
    canonical: dict[str, Any]
    live_event: LiveMonitorEventRequest
    source_type: str
    warning: str | None
    missing_metadata: list[str]
    recommendations: list[str]
    correlation_strength: str
    correlation_keys: dict[str, Any]
    safety_preview: live_monitor_safety_service.LiveSafetyResult


_INTEGRATION_EVENT_STORE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_INTEGRATION_EVENT_STORE_LOCK = RLock()


def _hash_payload(req: IntegrationEventIngestRequest) -> str:
    blob = req.model_dump(mode="json", exclude_none=True)
    serialized = json.dumps(blob, sort_keys=True, default=str)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _store_canonical(record: dict[str, Any]) -> None:
    with _INTEGRATION_EVENT_STORE_LOCK:
        event_id = record["integration_event_id"]
        _INTEGRATION_EVENT_STORE[event_id] = record
        _INTEGRATION_EVENT_STORE.move_to_end(event_id)
        limit = max(1, get_settings().integration_event_store_max)
        while len(_INTEGRATION_EVENT_STORE) > limit:
            _INTEGRATION_EVENT_STORE.popitem(last=False)


def _safe_summary(record: dict[str, Any]) -> dict[str, Any]:
    safe = {key: value for key, value in record.items() if not key.startswith("_")}
    safe.setdefault("schema_version", INTEGRATION_SCHEMA_VERSION)
    return safe


# Columns on `IntegrationEvent` that mirror a same-named key in the safe
# record dict built by `ingest_event`. `event_id` is derived, not stored,
# since it always equals `integration_event_id`.
_INTEGRATION_EVENT_COLUMNS: tuple[str, ...] = (
    "schema_version",
    "source_name",
    "source_tool",
    "source_type",
    "source_format",
    "external_alert_id",
    "external_incident_id",
    "event_time",
    "received_at",
    "service_name",
    "endpoint",
    "environment",
    "event_type",
    "sensitive_type",
    "masked_value",
    "severity",
    "confidence",
    "message_summary",
    "evidence_reference",
    "trace_id",
    "trace_fingerprint",
    "correlation_fingerprint_method",
    "correlation_fingerprint_version",
    "source_time_quality",
    "source_time_inferred",
    "source_timezone_name",
    "tags",
    "raw_payload_hash",
    "safety_status",
    "sensitive_types",
    "masked_values",
    "correlation_keys",
    "linked_alert_id",
    "linked_incident_id",
    "missing_metadata",
    "recommendations",
    "correlation_strength",
    "warning",
    "client_event_id",
)


def _persist_integration_event(db: Session, record: dict[str, Any]) -> None:
    """Durably persist the safe `record` so it survives a process restart.

    The in-memory `_INTEGRATION_EVENT_STORE` OrderedDict remains a
    read-through cache only; this table (`integration_events`) is the source
    of truth `get_event_record` falls back to on a cache miss.
    """

    integration_event_id = record["integration_event_id"]
    existing = db.scalar(
        select(IntegrationEvent).where(
            IntegrationEvent.integration_event_id == integration_event_id
        )
    )
    row = existing or IntegrationEvent(integration_event_id=integration_event_id)
    for column in _INTEGRATION_EVENT_COLUMNS:
        if column in record:
            setattr(row, column, record[column])
    db.add(row)
    db.flush()


def _record_from_row(row: IntegrationEvent) -> dict[str, Any]:
    record: dict[str, Any] = {
        "integration_event_id": row.integration_event_id,
        "event_id": row.integration_event_id,
    }
    for column in _INTEGRATION_EVENT_COLUMNS:
        record[column] = getattr(row, column)
    return record


def get_event_record(db: Session | None, integration_event_id: str) -> dict[str, Any] | None:
    """Look up a safe event record, checking the in-memory cache before the DB.

    `db` is optional only so this can still be called from purely in-process
    contexts (e.g. cache-hit paths in tests); a cache miss with `db=None`
    returns `None` rather than raising, since there is nowhere else to look.
    """

    with _INTEGRATION_EVENT_STORE_LOCK:
        record = _INTEGRATION_EVENT_STORE.get(integration_event_id)
        if record:
            _INTEGRATION_EVENT_STORE.move_to_end(integration_event_id)
    if record:
        return _safe_summary(record)
    if db is None:
        return None
    row = db.scalar(
        select(IntegrationEvent).where(
            IntegrationEvent.integration_event_id == integration_event_id
        )
    )
    if row is None:
        return None
    record = _record_from_row(row)
    with _INTEGRATION_EVENT_STORE_LOCK:
        _INTEGRATION_EVENT_STORE[integration_event_id] = record
        _INTEGRATION_EVENT_STORE.move_to_end(integration_event_id)
    return _safe_summary(record)


def get_safe_event_read(db: Session | None, integration_event_id: str) -> IntegrationEventSafeRead | None:
    record = get_event_record(db, integration_event_id)
    return IntegrationEventSafeRead(**record) if record else None


def clear_event_store() -> None:
    """Clear the in-memory cache only; the DB-backed table is untouched.

    Used by tests to reset per-test cache state, and to prove the durable
    store (not the cache) is what backs a lookup after a simulated restart.
    """

    with _INTEGRATION_EVENT_STORE_LOCK:
        _INTEGRATION_EVENT_STORE.clear()


def _normalise_source_type(req: IntegrationEventIngestRequest, canonical: dict[str, Any]) -> tuple[str, str | None]:
    supplied = (req.source_type or "").strip().lower()
    if supplied in ACCEPTED_SOURCE_TYPES:
        return supplied, None
    if supplied:
        return "custom", "Unknown source_type was processed as custom."

    event_type = str(canonical.get("event_type") or "").lower()
    source_format = str(canonical.get("source_format") or "").lower()
    metadata_keys = {str(key).lower() for key in req.metadata}
    if "scanner" in event_type or "finding" in event_type:
        inferred = "scanner_finding"
    elif "retest" in event_type:
        inferred = "retest_event"
    elif "deploy" in event_type or "deployment_version" in metadata_keys:
        inferred = "deployment_event"
    elif source_format in {"ocsf_json", "ecs_json", "splunk_hec_json"}:
        inferred = "siem_alert"
    else:
        inferred = "custom"
    return inferred, f"source_type was inferred as {inferred}."


def _find_nested(value: Any, names: set[str]) -> Any:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in names and child not in (None, ""):
                return child
        for child in value.values():
            found = _find_nested(child, names)
            if found not in (None, ""):
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_nested(child, names)
            if found not in (None, ""):
                return found
    return None


def _safe_scalar(value: Any) -> str | None:
    if value in (None, ""):
        return None
    result = live_monitor_safety_service.scan_and_mask_text(str(value))
    if not result.safe:
        return None
    return result.masked_text[:512]


def _metadata_advice(
    req: IntegrationEventIngestRequest,
    canonical: dict[str, Any],
) -> tuple[list[str], list[str], str, dict[str, Any]]:
    missing: list[str] = []
    recommendations: list[str] = []
    for field, recommendation in (
        ("service_name", "Add service_name for better correlation."),
        ("endpoint", "Add endpoint for better likely-cause ranking."),
        ("event_time", "Add event_time for stronger timing evidence."),
    ):
        if not canonical.get(field):
            missing.append(field)
            recommendations.append(recommendation)

    combined_metadata: dict[str, Any] = {}
    combined_metadata.update(req.metadata or {})
    if req.payload:
        combined_metadata["vendor_payload"] = req.payload
    deployment_version = _find_nested(
        combined_metadata,
        {"deployment_version", "release_version", "version"},
    )
    transaction_reference = _find_nested(
        combined_metadata,
        {"transaction_reference", "transaction_ref", "transaction_id"},
    )
    trace_id = canonical.get("trace_id") or _find_nested(
        combined_metadata,
        {"trace_id", "trace.id"},
    )
    request_id = _find_nested(combined_metadata, {"request_id", "req_id"})
    correlation_id = _find_nested(
        combined_metadata, {"correlation_id", "correlation.id"}
    )
    session_reference = _find_nested(
        combined_metadata, {"session_id", "session_reference"}
    )
    commit_reference = _find_nested(
        combined_metadata, {"commit_sha", "commit_reference", "commit_hash", "git_commit"}
    )
    configuration_version = _find_nested(
        combined_metadata, {"configuration_version", "config_version"}
    )
    host_reference = _find_nested(
        combined_metadata, {"host", "hostname", "host_reference", "instance_id"}
    )
    if not deployment_version:
        recommendations.append("Add deployment_version for CI/CD correlation.")
    if not trace_id and not transaction_reference:
        recommendations.append(
            "Add trace_id or transaction reference for timeline reconstruction."
        )

    event_time_value = canonical.get("event_time")
    keys: dict[str, Any] = {
        "source_name": req.source_name,
        "service_name": canonical.get("service_name"),
        "endpoint": canonical.get("endpoint"),
        "environment": canonical.get("environment"),
        # Stored as an ISO string, not a `datetime`, since this dict is
        # persisted directly into a JSONB column (`integration_events.
        # correlation_keys`) and plain `json.dumps` cannot serialize
        # `datetime` objects.
        "event_time": event_time_value.isoformat() if isinstance(event_time_value, datetime) else event_time_value,
    }
    if deployment_version:
        keys["deployment_version"] = _safe_scalar(deployment_version)
    keys.update(
        correlation_fingerprint_service.fingerprint_keys(
            {
                "trace_id": trace_id,
                "request_id": request_id,
                "correlation_id": correlation_id,
                "transaction_reference": transaction_reference,
                "session_reference": session_reference,
            }
        )
    )
    if commit_reference:
        keys["commit_reference"] = _safe_scalar(commit_reference)
    if configuration_version:
        keys["configuration_version"] = _safe_scalar(configuration_version)
    if host_reference:
        keys["host_reference"] = _safe_scalar(host_reference)
    keys = {key: value for key, value in keys.items() if value not in (None, "")}

    core_complete = all(canonical.get(field) for field in ("service_name", "endpoint", "event_time"))
    supporting_key = bool(deployment_version or keys.get("trace_id_fingerprint") or keys.get("transaction_reference_fingerprint"))
    if core_complete and supporting_key:
        strength = "strong"
    elif core_complete:
        strength = "moderate"
    else:
        strength = "limited"
    return missing, list(dict.fromkeys(recommendations)), strength, keys


def prepare_event(
    req: IntegrationEventIngestRequest,
    *,
    source_name_override: str | None = None,
) -> PreparedIntegrationEvent:
    canonical = integration_mapping_service.map_inbound_to_canonical(req)
    if source_name_override:
        req.source_name = source_name_override
        req.source_tool = source_name_override[:128]
        canonical["source_tool"] = req.source_tool
    source_type, warning = _normalise_source_type(req, canonical)
    missing, recommendations, strength, correlation_keys = _metadata_advice(req, canonical)
    message = str(canonical.get("message") or req.message or "Structured integration event")
    live_format = canonical.get("source_format") or "generic_json"
    if live_format not in live_ingestion_adapter_service.SUPPORTED_LIVE_SOURCE_FORMATS:
        live_format = "generic_json"
    live_metadata = dict(req.metadata or {})
    if req.tags:
        live_metadata["integration_tags"] = list(req.tags)
    live_event = LiveMonitorEventRequest(
        source_type=source_type,
        source_name=req.source_name,
        source_format=live_format,
        service_name=canonical.get("service_name"),
        endpoint=canonical.get("endpoint"),
        environment=canonical.get("environment"),
        timestamp=canonical.get("event_time"),
        message=message,
        metadata=live_metadata,
        payload=req.payload,
        trace_id=str(trace_id)[:128] if (trace_id := canonical.get("trace_id")) else None,
    )
    event_text = live_ingestion_adapter_service.extract_event_text(live_event)
    safety_preview = live_monitor_safety_service.scan_and_mask_text(event_text)
    return PreparedIntegrationEvent(
        canonical=canonical,
        live_event=live_event,
        source_type=source_type,
        warning=warning,
        missing_metadata=missing,
        recommendations=recommendations,
        correlation_strength=strength,
        correlation_keys=correlation_keys,
        safety_preview=safety_preview,
    )


def preview_event(
    req: IntegrationEventIngestRequest,
    *,
    source_name_override: str | None = None,
) -> dict[str, Any]:
    prepared = prepare_event(req, source_name_override=source_name_override)
    preview = prepared.safety_preview
    return {
        "valid": preview.safe,
        "detected_source_type": prepared.source_type,
        "required_fields_missing": [],
        "safety_status": "safe" if preview.safe else "rejected",
        "would_create_alert": bool(preview.safe and preview.matches),
        "missing_metadata": prepared.missing_metadata,
        "recommendations": prepared.recommendations,
        "reason": preview.reason if not preview.safe else None,
    }


def _create_safe_evidence_metadata(
    db: Session,
    *,
    source_name: str,
    source_format: str,
    integration_event_id: str,
    payload_hash: str,
    actor_id: int | None,
    source_timestamp: datetime | None,
    collection_timestamp: datetime,
    evidence_type: EvidenceType = EvidenceType.SIEM_ALERT,
    collector_name: str = "integration_gateway",
    collector_version: str = "1",
    parser_name: str = "siem_import",
    source_event_id: str | None = None,
    trace_id: str | None = None,
    commit_sha: str | None = None,
    service_name: str | None = None,
    deployment_environment: str | None = None,
    provenance_source_system: str | None = None,
) -> EvidenceFile:
    record = EvidenceFile(
        evidence_id=f"EVD-INT-{uuid.uuid4().hex[:12].upper()}",
        file_name=f"integration-event-{integration_event_id}-{source_format}"[:512],
        evidence_type=evidence_type,
        source_system=source_name[:255],
        file_hash=payload_hash,
        uploaded_by=actor_id,
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=None,
    )
    db.add(record)
    db.flush()
    from app.services import evidence_provenance_service
    evidence_provenance_service.record_system_provenance(
        db,
        record.evidence_id,
        source_system=provenance_source_system or source_name,
        source_format=source_format,
        collector_name=collector_name,
        collector_version=collector_version,
        parser_name=parser_name,
        parser_version="1",
        source_timestamp=source_timestamp,
        collection_timestamp=collection_timestamp,
        source_event_id=source_event_id,
        trace_id=trace_id,
        commit_sha=commit_sha,
        service_name=service_name,
        deployment_environment=deployment_environment,
        commit=False,
        append_integrity=True,
    )
    return record


def _safe_tags(tags: list[str]) -> list[str]:
    safe: list[str] = []
    for tag in tags:
        masked = _safe_scalar(tag)
        if masked:
            safe.append(masked[:128])
    return list(dict.fromkeys(safe))


def ingest_event(
    db: Session,
    req: IntegrationEventIngestRequest,
    *,
    actor_id: int | None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    source_name_override: str | None = None,
    client_event_id: str | None = None,
    evidence_type: EvidenceType | None = None,
    collector_name: str | None = None,
    collector_version: str | None = None,
    source_event_id: str | None = None,
    trace_id: str | None = None,
    commit_sha: str | None = None,
    source_time_quality_override: str | None = None,
    provenance_source_system: str | None = None,
) -> IngestionOutcome:
    prepared = prepare_event(req, source_name_override=source_name_override)
    live_result = live_monitor_service.process_event(
        db,
        prepared.live_event,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        commit=False,
    )
    if live_result.status == "rejected":
        audit_service.log_action(
            db,
            action="integration_event_rejected",
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            target_type="integration_event",
            details={
                "source_name": req.source_name,
                "source_format": req.source_format,
                "reason": "payload_failed_safety_validation",
            },
        )
        db.commit()
        return IngestionOutcome(
            status="rejected",
            safety_status="rejected",
            integration_event_id=None,
            canonical=None,
            reason=live_result.reason,
            violation_codes=["safety_validation"],
            evidence_id=None,
            missing_metadata=prepared.missing_metadata,
            recommendations=prepared.recommendations,
        )

    integration_event_id = f"INT-EVT-{uuid.uuid4().hex[:12].upper()}"
    payload_hash = _hash_payload(req)
    received_at = datetime.now(UTC)
    raw_source_time = prepared.live_event.timestamp
    source_was_naive = raw_source_time is not None and raw_source_time.tzinfo is None
    source_time = (
        None
        if raw_source_time is None
        else raw_source_time.replace(tzinfo=UTC)
        if source_was_naive
        else raw_source_time.astimezone(UTC)
    )
    source_time_quality = source_time_quality_override or (
        "inferred" if source_time is None else ("reported_assumed_utc" if source_was_naive else "reported_utc")
    )
    evidence = _create_safe_evidence_metadata(
        db,
        source_name=req.source_name or "external-source",
        source_format=req.source_format,
        integration_event_id=integration_event_id,
        payload_hash=payload_hash,
        actor_id=actor_id,
        source_timestamp=source_time,
        collection_timestamp=received_at,
        evidence_type=evidence_type or EvidenceType.SIEM_ALERT,
        collector_name=collector_name or "integration_gateway",
        collector_version=collector_version or "1",
        source_event_id=source_event_id,
        trace_id=trace_id,
        commit_sha=commit_sha,
        service_name=prepared.canonical.get("service_name"),
        deployment_environment=prepared.canonical.get("environment"),
        provenance_source_system=provenance_source_system,
    )
    masked_values = list(live_result.masked_values or [])
    sensitive_types = list(live_result.sensitive_types or [])
    summary = (
        live_result.alert.alert_summary
        if live_result.alert
        else "Integration event received and normalised safely. No privacy alert was created."
    )
    correlation_keys = prepared.correlation_keys
    deployment_version = (correlation_keys.get("deployment_version") or "")[:64] or None
    normalised = NormalizedEvent(
        event_id=integration_event_id,
        evidence_id=evidence.evidence_id,
        timestamp=source_time or received_at,
        source_type=prepared.source_type,
        service_name=prepared.canonical.get("service_name"),
        endpoint=prepared.canonical.get("endpoint"),
        release_version=deployment_version,
        event_type=prepared.canonical.get("event_type") or prepared.source_type,
        raw_reference=payload_hash,
        masked_message=summary,
        severity=live_alert_service.normalize_severity(prepared.canonical.get("severity")),
        linked_incident_id=None,
        trace_id=None,
        request_id=None,
        correlation_id=None,
        trace_fingerprint=(correlation_keys.get("trace_id_fingerprint") or "")[:128] or None,
        request_fingerprint=(correlation_keys.get("request_id_fingerprint") or "")[:128] or None,
        correlation_fingerprint=(correlation_keys.get("correlation_id_fingerprint") or "")[:128] or None,
        correlation_fingerprint_method=correlation_keys.get("fingerprint_method"),
        correlation_fingerprint_version=correlation_keys.get("fingerprint_version"),
        transaction_reference_hash=(correlation_keys.get("transaction_reference_fingerprint") or "")[:128] or None,
        session_reference_hash=(correlation_keys.get("session_reference_fingerprint") or "")[:128] or None,
        deployment_version=deployment_version,
        commit_reference=(correlation_keys.get("commit_reference") or "")[:128] or None,
        configuration_version=(correlation_keys.get("configuration_version") or "")[:64] or None,
        host_reference=(correlation_keys.get("host_reference") or "")[:255] or None,
        event_time_source="source_event" if source_time else "server_ingestion",
        time_quality=source_time_quality,
        time_inferred=source_time is None,
        timezone_name="assumed_UTC" if source_was_naive else ("UTC" if source_time else None),
    )
    db.add(normalised)

    if live_result.alert_id:
        alert = live_alert_service.get_alert(db, live_result.alert_id)
        if alert:
            alert.evidence_id = evidence.evidence_id
            alert.ingestion_source = "integration_gateway"
            alert.missing_metadata = prepared.missing_metadata
            alert.correlation_recommendations = prepared.recommendations
            alert.evidence_strength = prepared.correlation_strength

    prepared.correlation_keys["sensitive_types"] = sensitive_types
    safe_tags = _safe_tags(list(prepared.canonical.get("tags") or []))
    record: dict[str, Any] = {
        "schema_version": INTEGRATION_SCHEMA_VERSION,
        "integration_event_id": integration_event_id,
        "event_id": integration_event_id,
        "source_name": req.source_name,
        "source_tool": req.source_tool,
        "source_type": prepared.source_type,
        "source_format": req.source_format,
        "external_alert_id": prepared.canonical.get("external_alert_id"),
        "external_incident_id": prepared.canonical.get("external_incident_id"),
        "event_time": source_time,
        "received_at": received_at,
        "source_time_quality": source_time_quality,
        "source_time_inferred": source_time is None,
        "source_timezone_name": "assumed_UTC" if source_was_naive else ("UTC" if source_time else None),
        "service_name": prepared.canonical.get("service_name"),
        "endpoint": prepared.canonical.get("endpoint"),
        "environment": prepared.canonical.get("environment"),
        "event_type": prepared.canonical.get("event_type") or prepared.source_type,
        "sensitive_type": sensitive_types[0] if sensitive_types else prepared.canonical.get("sensitive_type"),
        "masked_value": masked_values[0] if masked_values else prepared.canonical.get("masked_value"),
        "severity": prepared.canonical.get("severity"),
        "confidence": prepared.canonical.get("confidence"),
        "message": summary,
        "message_summary": summary,
        "evidence_reference": evidence.evidence_id,
        "source_ip": None,
        "destination_ip": None,
        "user_or_actor": None,
        "trace_id": trace_id,
        "trace_fingerprint": prepared.correlation_keys.get("trace_id_fingerprint"),
        "correlation_fingerprint_method": prepared.correlation_keys.get("fingerprint_method"),
        "correlation_fingerprint_version": prepared.correlation_keys.get("fingerprint_version"),
        "tags": safe_tags,
        "raw_payload_hash": payload_hash,
        "safety_status": "safe",
        "sensitive_types": sensitive_types,
        "masked_values": masked_values,
        "correlation_keys": prepared.correlation_keys,
        "linked_alert_id": live_result.alert_id,
        "linked_incident_id": None,
        "missing_metadata": prepared.missing_metadata,
        "recommendations": prepared.recommendations,
        "correlation_strength": prepared.correlation_strength,
        "warning": prepared.warning,
        "client_event_id": client_event_id,
    }
    if live_result.alert_id:
        from app.services import privacy_ingestion_pipeline_service

        privacy_ingestion_pipeline_service.attach_alert_classifications(
            db,
            live_result.alert_id,
            evidence_id=evidence.evidence_id,
            normalized_event_id=integration_event_id,
        )
    audit_service.log_action(
        db,
        action="integration_event_ingested",
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="integration_event",
        target_id=integration_event_id,
        details={
            "source_name": req.source_name,
            "source_format": req.source_format,
            "source_type": prepared.source_type,
            "raw_payload_hash": payload_hash,
            "evidence_id": evidence.evidence_id,
            "alert_id": live_result.alert_id,
            "alert_created": bool(live_result.alert_id),
            "missing_metadata": prepared.missing_metadata,
        },
    )
    _persist_integration_event(db, record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if client_event_id and req.source_name:
            existing = db.scalar(
                select(IntegrationEvent).where(
                    IntegrationEvent.source_name == req.source_name,
                    IntegrationEvent.client_event_id == client_event_id,
                )
            )
            if existing is not None:
                return IngestionOutcome(
                    status="duplicate",
                    safety_status="safe",
                    integration_event_id=existing.integration_event_id,
                    canonical=_record_from_row(existing),
                    reason="duplicate",
                    violation_codes=[],
                    evidence_id=existing.evidence_reference,
                    alert_created=bool(existing.linked_alert_id),
                    alert_id=existing.linked_alert_id,
                    missing_metadata=list(existing.missing_metadata or []),
                    recommendations=list(existing.recommendations or []),
                )
        raise
    _store_canonical(record)
    return IngestionOutcome(
        status="accepted",
        safety_status="safe",
        integration_event_id=integration_event_id,
        canonical=record,
        reason=None,
        violation_codes=[],
        evidence_id=evidence.evidence_id,
        alert_created=bool(live_result.alert_id),
        alert_id=live_result.alert_id,
        missing_metadata=prepared.missing_metadata,
        recommendations=prepared.recommendations,
    )
