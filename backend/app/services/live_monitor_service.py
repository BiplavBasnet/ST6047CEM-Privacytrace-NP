"""Live Privacy Monitor orchestration."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Detection, EvidenceFile, Incident, NormalizedEvent
from app.models.enums import EvidenceType, IncidentStatus, ParsingStatus, Severity
from app.models.privacy_alert import PrivacyAlert
from app.config import synthetic_demo_actions_allowed
from app.schemas.live_monitor_schema import (
    SUPPORTED_LIVE_INPUT_MODES,
    LiveAlertDismissResponse,
    LiveAlertIncidentResponse,
    LiveAlertListResponse,
    LiveMonitorBatchItemResponse,
    LiveMonitorBatchResponse,
    LiveMonitorEventRequest,
    LiveMonitorEventResponse,
    LiveMonitorRetestResponse,
    LiveMonitorStartRequest,
    LiveMonitorStatusResponse,
)
from app.services import (
    audit_service,
    causality_engine,
    correlation_fingerprint_service,
    detection_service,
    live_alert_grouping_service,
    live_alert_service,
    live_ingestion_adapter_service,
    live_monitor_config_service,
    live_monitor_safety_service,
    ingestion_service,
    privacy_ingestion_pipeline_service,
)
from app.services import sensitive_exposure_engine as exposure_engine

MAX_EVENT_BYTES = 64 * 1024

# Maps the free-form `LiveMonitorEventRequest.source_type` string onto the
# exposure engine's `source_type` vocabulary (see
# `sensitive_exposure_engine._SOURCE_TYPE_LOCATION_MAP`) so Live Monitor and
# Evidence detection share one exposure-location inference. Unrecognised
# source types default to "application_log" — the conservative assumption
# that an observed live event has reached a durable, widely readable log,
# matching this module's historical behaviour of treating any detected value
# in live event text as a possible exposure regardless of channel.
_LIVE_SOURCE_TYPE_ENGINE_MAP: dict[str, str] = {
    "api_log": "application_log",
    "application_log": "application_log",
    "runtime_log": "runtime_log",
    "log": "application_log",
    "http_log": "application_log",
    "syslog_like": "application_log",
    "request_header": "request_header",
    "request_body": "request_body",
    "response_body": "response_body",
    "query_string": "query_string",
    "database": "database_field",
    "database_field": "database_field",
    "webhook": "webhook",
    "siem_alert": "siem_import",
    "siem_import": "siem_import",
    "scanner_finding": "scanner_bridge",
    "scanner_bridge": "scanner_bridge",
    "deployment_event": "application_log",
    "retest_event": "application_log",
    "custom": "application_log",
}

_ALERTABLE_EXPOSURE_DECISIONS = {"unsafe_exposure", "uncertain"}


def _engine_source_type(source_type: str | None) -> str:
    return _LIVE_SOURCE_TYPE_ENGINE_MAP.get(
        str(source_type or "").strip().casefold(), "application_log"
    )


def _severity_from_findings(findings: list[dict[str, Any]]) -> Severity:
    order = list(Severity)
    severities = [detection_service.severity_for_finding(f) for f in findings]
    return max(severities, key=order.index) if severities else Severity.MEDIUM


def _alert_finding_snapshot(finding: dict[str, Any]) -> dict[str, Any]:
    """Safe (no raw value) per-finding snapshot stored on `PrivacyAlert.alert_findings`."""

    return {
        "sensitive_type": finding["sensitive_type"],
        "confidence_score": finding["confidence_score"],
        "confidence_level": finding["confidence_level"],
        "value_fingerprint": finding.get("value_fingerprint"),
        "masked_preview": finding.get("masked_preview"),
        "severity": detection_service.severity_for_finding(finding).value,
        "exposure_location": finding.get("exposure_location"),
    }


def _meta_get(meta: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = meta.get(key)
        if value is None and "." in key:
            # nested alias e.g. trace.id
            cur: Any = meta
            for part in key.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    cur = None
                    break
                cur = cur[part]
            value = cur
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text[:128]
    return None


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def extract_correlation_keys(event: LiveMonitorEventRequest) -> dict[str, str]:
    """Resolve safe metadata and HMAC-only correlation identifiers."""

    meta = dict(event.metadata or {})
    if event.payload and isinstance(event.payload, dict):
        # Shallow merge so payload aliases are visible without overwriting metadata.
        for key, value in event.payload.items():
            meta.setdefault(key, value)
    identifiers = {
        "trace_id": event.trace_id or _meta_get(meta, "trace_id", "trace.id"),
        "request_id": event.request_id or _meta_get(meta, "request_id", "req_id"),
        "correlation_id": event.correlation_id or _meta_get(meta, "correlation_id", "correlation.id"),
        "transaction_reference": _meta_get(meta, "transaction_reference", "transaction_ref", "transaction_id"),
        "session_reference": _meta_get(meta, "session_id", "session_reference"),
    }
    keys = correlation_fingerprint_service.fingerprint_keys(identifiers)
    deployment_version = event.deployment_version or _meta_get(
        meta, "deployment_version", "release_version", "version"
    )
    configuration_version = event.configuration_version or _meta_get(
        meta, "configuration_version", "config_version"
    )
    if deployment_version:
        keys["deployment_version"] = deployment_version[:64]
    if configuration_version:
        keys["configuration_version"] = configuration_version[:64]
    return keys


class LiveMonitorError(Exception):
    pass


class LiveAlertNotFoundError(LiveMonitorError):
    pass


class LiveIncidentNotFoundError(LiveMonitorError):
    pass


class LiveAlertStateError(LiveMonitorError):
    pass


class LiveMonitorDemoActionNotAllowed(LiveMonitorError):
    pass


class LiveMonitorNotRunningError(LiveMonitorError):
    pass


def _hash_payload(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, default=str)
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def _payload_size(value: Any) -> int:
    return len(json.dumps(value, default=str).encode("utf-8"))


def _event_hash(event: LiveMonitorEventRequest) -> str:
    return _hash_payload(event.model_dump(mode="json"))


def _safe_summary(*, event: LiveMonitorEventRequest, sensitive_types: list[str], masked_values: list[str]) -> str:
    service = event.service_name or event.source_name or "unknown service"
    endpoint = event.endpoint or "unknown endpoint"
    types = ", ".join(sensitive_types) if sensitive_types else "none"
    values = ", ".join(masked_values[:5]) if masked_values else "none"
    return (
        f"Possible privacy exposure detected in a passive live log/event copy from {service} "
        f"at {endpoint}. Sensitive types: {types}. Masked values: {values}. "
        "Human review is required."
    )


def _actor_kwargs(actor_id: int | None, actor_email: str | None, actor_role: str | None) -> dict:
    return {"actor_id": actor_id, "actor_email": actor_email, "actor_role": actor_role}


def get_status(db: Session) -> LiveMonitorStatusResponse:
    state = live_monitor_config_service.get_state(db)
    count = db.scalar(select(func.count(PrivacyAlert.id))) or 0
    last_alert = db.scalar(select(func.max(PrivacyAlert.alert_time)))
    return LiveMonitorStatusResponse(
        running=state.running,
        mode=state.mode,
        supported_input_modes=list(SUPPORTED_LIVE_INPUT_MODES),
        last_event_received_at=state.last_event_received_at,
        event_count=state.event_count,
        alert_count=int(count),
        last_alert_time=state.last_alert_created_at or last_alert,
        safety_status=state.safety_status,
    )


def start_monitor(db: Session, body: LiveMonitorStartRequest, *, actor_id: int | None, actor_email: str | None, actor_role: str | None):
    state = live_monitor_config_service.start_monitor(
        db,
        mode=body.mode,
        source_name=body.source_name,
        environment=body.environment,
        safe_mode=body.safe_mode,
    )
    audit_service.log_action(
        db,
        action="live_monitor_started",
        target_type="live_monitor",
        target_id=body.source_name or "http_ingestion",
        details={"mode": body.mode, "environment": body.environment, "safe_mode": body.safe_mode},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return state


def stop_monitor(db: Session, *, actor_id: int | None, actor_email: str | None, actor_role: str | None):
    state = live_monitor_config_service.stop_monitor(db)
    audit_service.log_action(
        db,
        action="live_monitor_stopped",
        target_type="live_monitor",
        target_id="http_ingestion",
        details={"mode": state.mode},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return state


def process_event(
    db: Session,
    event: LiveMonitorEventRequest,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
    commit: bool = True,
) -> LiveMonitorEventResponse:
    if not live_monitor_config_service.get_state(db).running:
        raise LiveMonitorNotRunningError(
            "Live Privacy Monitor ingestion is stopped. Start the monitor before submitting events."
        )
    received_at = datetime.now(UTC)
    live_monitor_config_service.record_event_received(db)
    raw_hash = _event_hash(event)
    if _payload_size(event.model_dump(mode="json")) > MAX_EVENT_BYTES:
        audit_service.log_action(
            db,
            action="live_monitor_event_rejected",
            target_type="live_monitor_event",
            target_id=None,
            details={"reason": "payload_too_large", "source_format": event.source_format},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit() if commit else db.flush()
        return LiveMonitorEventResponse(
            status="rejected",
            safety_status="rejected",
            raw_event_hash=raw_hash,
            reason="Live event payload exceeds the configured size limit.",
            message="Event rejected safely. No raw event content was stored or returned.",
        )

    fmt = live_ingestion_adapter_service.validate_source_format(event.source_format)
    text = live_ingestion_adapter_service.extract_event_text(event)
    safety = live_monitor_safety_service.scan_and_mask_text(text)
    if not safety.safe:
        audit_service.log_action(
            db,
            action="live_monitor_event_rejected",
            target_type="live_monitor_event",
            target_id=None,
            details={"reason": safety.reason or "unsafe_wording", "source_format": fmt, "violation_codes": safety.violation_codes},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit() if commit else db.flush()
        return LiveMonitorEventResponse(
            status="rejected",
            safety_status="rejected",
            raw_event_hash=raw_hash,
            reason=safety.reason or "Live event was rejected by the safety guard.",
            message="Event rejected safely. No raw event content was stored or returned.",
        )
    if not live_monitor_safety_service.assert_masked_output_safe(safety.masked_text):
        audit_service.log_action(
            db,
            action="live_monitor_event_rejected",
            target_type="live_monitor_event",
            target_id=None,
            details={"reason": "masking_failed", "source_format": fmt},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit() if commit else db.flush()
        return LiveMonitorEventResponse(
            status="rejected",
            safety_status="rejected",
            raw_event_hash=raw_hash,
            reason="Live event could not be safely masked.",
            message="Event rejected safely. No raw event content was stored or returned.",
        )

    # Classification decision now comes from one unified pipeline: the same
    # `sensitive_exposure_engine` Evidence detection uses. It sees both the
    # rendered event text and the structured payload/metadata in a single
    # pass, so this replaces the previous split between
    # `live_monitor_safety_service` regex matches (for alerting) and
    # `privacy_ingestion_pipeline_service.classify_fields` (for Nepal
    # taxonomy/contextual results). `classify_fields` below is still run
    # for its Nepal-taxonomy `SensitiveDataClassification` persistence side
    # effect (privacy impact/breach determination read those rows), but it no
    # longer decides whether an alert is created or what the alert reports.
    findings = exposure_engine.analyse(
        source_type=_engine_source_type(event.source_type),
        text=text,
        structured={"payload": event.payload or {}, "metadata": event.metadata or {}},
        service=event.service_name or event.source_name,
        endpoint=event.endpoint,
        environment=event.environment,
        event_time=event.timestamp,
    )
    actionable_findings = [
        finding for finding in findings if finding["exposure_decision"] in _ALERTABLE_EXPOSURE_DECISIONS
    ]

    contextual_results = privacy_ingestion_pipeline_service.classify_fields(
        {
            "payload": event.payload or {},
            "metadata": event.metadata or {},
        },
        source_context={
            "endpoint": event.endpoint or "",
            "source_service": event.service_name or event.source_name or "",
            "credential_status": "unknown",
        },
    )

    if not actionable_findings:
        audit_service.log_action(
            db,
            action="live_monitor_event_no_alert",
            target_type="live_monitor_event",
            target_id=None,
            details={"source_format": fmt, "source_name": event.source_name, "raw_event_hash": raw_hash},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit() if commit else db.flush()
        return LiveMonitorEventResponse(
            status="no_alert",
            safety_status="safe",
            raw_event_hash=raw_hash,
            message="No possible sensitive data exposure was detected. No privacy alert was created.",
        )

    sensitive_types = list(dict.fromkeys(f["sensitive_type"] for f in actionable_findings))
    masked_values = list(
        dict.fromkeys(f["masked_preview"] for f in actionable_findings if f.get("masked_preview"))
    )
    severity = _severity_from_findings(actionable_findings)
    top_finding = max(actionable_findings, key=lambda f: f["confidence_score"])
    alert_findings = [_alert_finding_snapshot(f) for f in actionable_findings]
    source_was_naive = event.timestamp is not None and event.timestamp.tzinfo is None
    source_event_time = _utc(event.timestamp)
    source_time_quality = "inferred" if source_event_time is None else ("reported_assumed_utc" if source_was_naive else "reported_utc")
    summary = _safe_summary(event=event, sensitive_types=sensitive_types, masked_values=masked_values)

    group_key = live_alert_grouping_service.compute_group_key(
        sensitive_type=top_finding["sensitive_type"],
        exposure_location=top_finding["exposure_location"],
        service=event.service_name or event.source_name,
        endpoint=event.endpoint,
        environment=event.environment,
    )
    correlation_keys = extract_correlation_keys(event)
    live_alert_grouping_service.acquire_group_claim(db, group_key)
    existing_alert = live_alert_grouping_service.find_open_alert(db, group_key, at=received_at)
    if existing_alert is not None:
        alert = live_alert_grouping_service.register_recurrence(
            db,
            existing_alert,
            observed_at=received_at,
            source_time_quality=source_time_quality,
            source_time_inferred=source_event_time is None,
            source_timezone_name="assumed_UTC" if source_was_naive else ("UTC" if source_event_time else None),
            source_event_time=source_event_time,
            sensitive_types=sensitive_types,
            masked_values=masked_values,
            confidence_score=top_finding["confidence_score"],
            confidence_level=top_finding["confidence_level"],
            alert_findings=alert_findings,
            trace_fingerprint=correlation_keys.get("trace_id_fingerprint"),
        )
        alert.raw_event_hash = raw_hash
        if correlation_keys:
            alert.correlation_keys = {**(alert.correlation_keys or {}), **correlation_keys}
        db.add(alert)
        audit_action = "live_privacy_alert_recurrence_recorded"
    else:
        alert = live_alert_service.create_alert(
            db,
            alert_time=source_event_time,
            source_type=event.source_type,
            source_name=event.source_name,
            source_format=fmt,
            service_name=event.service_name,
            endpoint=event.endpoint,
            environment=event.environment,
            severity=severity,
            sensitive_types=sensitive_types,
            masked_values=masked_values,
            raw_event_hash=raw_hash,
            alert_summary=summary,
            alert_group_key=group_key,
            exposure_location=top_finding["exposure_location"],
            confidence_score=top_finding["confidence_score"],
            confidence_level=top_finding["confidence_level"],
            alert_findings=alert_findings,
            correlation_keys=correlation_keys or None,
            trace_fingerprint=correlation_keys.get("trace_id_fingerprint"),
            observed_at=received_at,
            source_time_quality=source_time_quality,
            source_time_inferred=source_event_time is None,
            source_timezone_name="assumed_UTC" if source_was_naive else ("UTC" if source_event_time else None),
        )
        audit_action = "live_privacy_alert_created"
    privacy_ingestion_pipeline_service.persist_results(
        db,
        contextual_results,
        privacy_alert_id=alert.alert_id,
        actor_id=actor_id,
    )
    live_monitor_config_service.record_alert_created(db, alert.alert_time)
    audit_service.log_action(
        db,
        action=audit_action,
        target_type="privacy_alert",
        target_id=alert.alert_id,
        details={
            "source_format": fmt,
            "source_name": event.source_name,
            "sensitive_types": alert.sensitive_types,
            "severity": severity.value,
            "raw_event_hash": raw_hash,
            "alert_group_key": group_key,
            "repeat_count": alert.repeat_count,
        },
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    if commit:
        db.commit()
        db.refresh(alert)
    else:
        db.flush()
    return LiveMonitorEventResponse(
        status="alert_created",
        safety_status="safe",
        alert_id=alert.alert_id,
        alert=live_alert_service.alert_to_read(alert),
        sensitive_types=alert.sensitive_types,
        masked_values=alert.masked_values,
        raw_event_hash=raw_hash,
        message="Privacy alert created with masked values only. Human review is required.",
    )


def process_test_event(db: Session, *, actor_id: int | None, actor_email: str | None, actor_role: str | None) -> LiveMonitorEventResponse:
    if not synthetic_demo_actions_allowed():
        raise LiveMonitorDemoActionNotAllowed(
            "Synthetic test events are available only in development, test, or demo environments."
        )
    phone = "984" + "1234" + "567"
    wallet = "WALLET-NP-" + "88291"
    txn = "TXN-NP-2026-" + "77881"
    event = LiveMonitorEventRequest(
        source_type="api_log",
        source_name="wallet-service",
        source_format="generic_json",
        service_name="wallet-service",
        endpoint="/wallet/transfer",
        environment="demo",
        timestamp=datetime.now(UTC),
        message=f"Synthetic demo live event phone={phone} wallet={wallet} txn={txn}",
        metadata={"scenario": "live_monitor_test_event"},
    )
    return process_event(db, event, actor_id=actor_id, actor_email=actor_email, actor_role=actor_role)


def process_batch(
    db: Session,
    events: list[LiveMonitorEventRequest],
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> LiveMonitorBatchResponse:
    results: list[LiveMonitorBatchItemResponse] = []
    alert_count = 0
    no_alert_count = 0
    rejected_count = 0
    for index, event in enumerate(events):
        try:
            outcome = process_event(db, event, actor_id=actor_id, actor_email=actor_email, actor_role=actor_role)
        except live_ingestion_adapter_service.UnsupportedLiveMonitorFormatError as exc:
            rejected_count += 1
            results.append(
                LiveMonitorBatchItemResponse(
                    index=index,
                    status="rejected",
                    safety_status="rejected",
                    reason=str(exc),
                )
            )
            continue
        if outcome.status == "alert_created":
            alert_count += 1
        elif outcome.status == "no_alert":
            no_alert_count += 1
        else:
            rejected_count += 1
        results.append(
            LiveMonitorBatchItemResponse(
                index=index,
                status=outcome.status,
                safety_status=outcome.safety_status,
                alert_id=outcome.alert_id,
                reason=outcome.reason,
                sensitive_types=outcome.sensitive_types,
            )
        )
    return LiveMonitorBatchResponse(
        total=len(events),
        alert_count=alert_count,
        no_alert_count=no_alert_count,
        rejected_count=rejected_count,
        results=results,
    )


def list_alerts(db: Session, **filters) -> LiveAlertListResponse:
    rows = live_alert_service.list_alerts(db, **filters)
    return LiveAlertListResponse(alerts=[live_alert_service.alert_to_read(r) for r in rows], total=len(rows))


def get_alert_safe(db: Session, alert_id: str):
    alert = live_alert_service.get_alert(db, alert_id)
    if not alert:
        raise LiveAlertNotFoundError(f"Privacy alert not found: {alert_id}")
    return live_alert_service.alert_to_read(alert)


def _new_incident_id() -> str:
    return f"INC-LIVE-{uuid.uuid4().hex[:10].upper()}"


def _event_id() -> str:
    return f"EVT-LIVE-{uuid.uuid4().hex[:12].upper()}"


def _evidence_id() -> str:
    return f"EVD-LIVE-{uuid.uuid4().hex[:12].upper()}"


def _detection_id() -> str:
    return f"DET-LIVE-{uuid.uuid4().hex[:12].upper()}"


def _detection_fields_for_type(alert: PrivacyAlert, sensitive_type: str, fallback_masked_value: str) -> dict[str, Any]:
    """Per-type confidence/fingerprint/severity for a Detection derived from `alert`.

    Prefers the engine finding snapshot captured at alert creation/recurrence
    time (`PrivacyAlert.alert_findings`, see `_alert_finding_snapshot`) so
    Detection rows created when an alert is linked to an incident carry the
    real per-value confidence and HMAC fingerprint instead of a hardcoded
    confidence and a `None` fingerprint. Falls back to the alert's aggregate
    `confidence_score`/severity for alerts created before this snapshot
    existed.
    """

    finding = next(
        (item for item in (alert.alert_findings or []) if item.get("sensitive_type") == sensitive_type),
        None,
    )
    if finding:
        severity = Severity(finding["severity"]) if finding.get("severity") else alert.severity
        return {
            "raw_value_hash": finding.get("value_fingerprint"),
            "masked_value": finding.get("masked_preview") or fallback_masked_value,
            "confidence": finding.get("confidence_score", alert.confidence_score),
            "severity": severity,
            "detector_name": exposure_engine.ENGINE_VERSION,
        }
    return {
        "raw_value_hash": None,
        "masked_value": fallback_masked_value,
        "confidence": alert.confidence_score if alert.confidence_score is not None else 0.5,
        "severity": alert.severity,
        "detector_name": "live_monitor_regex_v1",
    }


def _ensure_alert_evidence(db: Session, alert: PrivacyAlert, incident_id: str) -> None:
    privacy_ingestion_pipeline_service.attach_alert_classifications(
        db,
        alert.alert_id,
        incident_id=incident_id,
    )
    if alert.evidence_id:
        evidence = db.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == alert.evidence_id))
        if evidence:
            evidence.linked_incident_id = incident_id
            db.add(evidence)
            event = db.scalar(
                select(NormalizedEvent).where(
                    NormalizedEvent.evidence_id == evidence.evidence_id
                )
            )
            if event:
                event.linked_incident_id = incident_id

            detections = list(
                db.scalars(
                    select(Detection).where(
                        Detection.evidence_id == evidence.evidence_id
                    )
                ).all()
            )
            if not detections:
                sensitive_types = [str(x) for x in (alert.sensitive_types or [])]
                masked_values = [str(x) for x in (alert.masked_values or [])]
                for idx, sensitive_type in enumerate(sensitive_types):
                    fallback_masked_value = masked_values[idx] if idx < len(masked_values) else "[masked]"
                    fields = _detection_fields_for_type(alert, sensitive_type, fallback_masked_value)
                    detection = Detection(
                        detection_id=_detection_id(),
                        incident_id=incident_id,
                        evidence_id=evidence.evidence_id,
                        normalized_event_id=event.event_id if event else None,
                        sensitive_type=sensitive_type,
                        **fields,
                    )
                    db.add(detection)
                    detections.append(detection)
            else:
                for detection in detections:
                    detection.incident_id = incident_id

            alert.detection_ids = [detection.detection_id for detection in detections]
            db.flush()
            return

    evidence_id = _evidence_id()
    evidence = EvidenceFile(
        evidence_id=evidence_id,
        file_name=f"live-monitor-alert-{alert.alert_id}.json",
        evidence_type=EvidenceType.SIEM_ALERT,
        source_system=(alert.source_name or "live_monitor")[:255],
        file_hash=alert.raw_event_hash,
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=incident_id,
    )
    db.add(evidence)
    corr = dict(alert.correlation_keys or {})
    event = NormalizedEvent(
        event_id=_event_id(),
        evidence_id=evidence_id,
        timestamp=alert.alert_time,
        source_type=alert.source_type,
        service_name=alert.service_name,
        endpoint=alert.endpoint,
        release_version=corr.get("deployment_version"),
        event_type="live_privacy_alert",
        raw_reference=f"privacy_alert:{alert.alert_id}",
        masked_message=alert.alert_summary,
        severity=alert.severity,
        linked_incident_id=incident_id,
        trace_id=None,
        request_id=None,
        correlation_id=None,
        trace_fingerprint=corr.get("trace_id_fingerprint"),
        request_fingerprint=corr.get("request_id_fingerprint"),
        correlation_fingerprint=corr.get("correlation_id_fingerprint"),
        correlation_fingerprint_method=corr.get("fingerprint_method"),
        correlation_fingerprint_version=corr.get("fingerprint_version"),
        event_time_source="source_event" if alert.first_source_event_time else "server_ingestion",
        time_quality=alert.source_time_quality,
        time_inferred=alert.source_time_inferred,
        timezone_name=alert.source_timezone_name,
        deployment_version=corr.get("deployment_version"),
        configuration_version=corr.get("configuration_version"),
    )
    db.add(event)
    db.flush()
    from app.services import evidence_provenance_service
    evidence_provenance_service.record_system_provenance(
        db,
        evidence_id,
        source_system=alert.source_name,
        source_format=alert.source_format,
        collector_name="live_monitor",
        parser_name="live_alert_normalizer",
        parser_version="1",
        source_timestamp=alert.alert_time,
        collection_timestamp=alert.received_at,
        commit=False,
        append_integrity=True,
    )

    detection_ids: list[str] = []
    sensitive_types = [str(x) for x in (alert.sensitive_types or [])]
    masked_values = [str(x) for x in (alert.masked_values or [])]
    for idx, sensitive_type in enumerate(sensitive_types):
        fallback_masked_value = masked_values[idx] if idx < len(masked_values) else "[masked]"
        fields = _detection_fields_for_type(alert, sensitive_type, fallback_masked_value)
        detection_id = _detection_id()
        db.add(
            Detection(
                detection_id=detection_id,
                incident_id=incident_id,
                evidence_id=evidence_id,
                normalized_event_id=event.event_id,
                sensitive_type=sensitive_type,
                **fields,
            )
        )
        detection_ids.append(detection_id)

    alert.evidence_id = evidence_id
    alert.detection_ids = detection_ids


def create_or_link_incident(
    db: Session,
    *,
    alert_id: str,
    mode: str,
    incident_id: str | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> LiveAlertIncidentResponse:
    alert = db.scalar(
        select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id).with_for_update()
    )
    if not alert:
        raise LiveAlertNotFoundError(f"Privacy alert not found: {alert_id}")
    if alert.status == "dismissed_false_positive":
        raise LiveAlertStateError("Dismissed alerts cannot be linked to incidents without reopening.")
    if alert.linked_incident_id:
        raise LiveAlertStateError(
            f"Privacy alert is already linked to incident {alert.linked_incident_id}."
        )

    if mode == "create_new":
        incident_id = _new_incident_id()
        from app.services import organisation_access_service as org_access

        incident = Incident(
            incident_id=incident_id,
            organisation_id=org_access.resolve_organisation_id(db),
            title=f"Possible privacy exposure in {alert.service_name or alert.source_name or 'live log stream'}",
            affected_endpoint=alert.endpoint,
            affected_service=alert.service_name or alert.source_name,
            status=IncidentStatus.NEW,
            severity=alert.severity,
            first_seen=alert.alert_time,
            last_seen=alert.alert_time,
            summary="A live privacy alert detected masked sensitive values in an API log/event copy. Human review is required.",
        )
        db.add(incident)
        db.flush()
    else:
        if not incident_id:
            raise LiveIncidentNotFoundError("incident_id is required when linking an existing incident.")
        incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
        if not incident:
            raise LiveIncidentNotFoundError(f"Incident not found: {incident_id}")

    alert.linked_incident_id = incident_id
    alert.status = "linked_to_incident"
    alert.human_review_required = True
    _ensure_alert_evidence(db, alert, incident_id)
    # Phase N: a newly linked live alert invalidates any existing root-cause
    # analysis ranking for this incident until it is re-run.
    causality_engine.mark_stale(
        db, incident_id, "A live privacy alert was linked since the last root-cause analysis."
    )
    privacy_ingestion_pipeline_service.refresh_exposure_profiles(
        db,
        incident_id,
        actor_id=actor_id,
    )
    from app.schemas.privacy_impact_schema import PrivacyImpactAssessRequest
    from app.services import privacy_impact_service
    privacy_impact_service.assess_incident(
        db,
        incident_id,
        PrivacyImpactAssessRequest(),
        actor_id=actor_id,
        commit=False,
    )
    db.add(alert)
    audit_service.log_action(
        db,
        action="live_privacy_alert_linked_to_incident",
        target_type="privacy_alert",
        target_id=alert.alert_id,
        details={"incident_id": incident_id, "mode": mode, "evidence_id": alert.evidence_id},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return LiveAlertIncidentResponse(
        alert_id=alert.alert_id,
        incident_id=incident_id,
        status=alert.status,
        message="Privacy alert linked as masked supporting evidence. Human review is required.",
    )


def dismiss_alert(
    db: Session,
    *,
    alert_id: str,
    reason: str | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> LiveAlertDismissResponse:
    alert = live_alert_service.get_alert(db, alert_id)
    if not alert:
        raise LiveAlertNotFoundError(f"Privacy alert not found: {alert_id}")
    if alert.linked_incident_id:
        raise LiveAlertStateError(
            "Alerts linked to incidents cannot be dismissed; record the decision through incident review."
        )
    if alert.status == "dismissed_false_positive":
        raise LiveAlertStateError("Privacy alert is already dismissed.")
    alert.status = "dismissed_false_positive"
    db.add(alert)
    audit_service.log_action(
        db,
        action="live_privacy_alert_dismissed",
        target_type="privacy_alert",
        target_id=alert.alert_id,
        details={"reason": reason or "No reason provided"},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return LiveAlertDismissResponse(
        alert_id=alert.alert_id,
        status=alert.status,
        message="Privacy alert dismissed without deleting the audit trail.",
    )


def record_live_retest_event(
    db: Session,
    *,
    incident_id: str,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> LiveMonitorRetestResponse:
    if not synthetic_demo_actions_allowed():
        raise LiveMonitorDemoActionNotAllowed(
            "Synthetic retest evidence is available only in development, test, or demo environments."
        )
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise LiveIncidentNotFoundError(f"Incident not found: {incident_id}")

    live_monitor_config_service.record_event_received(db)
    recorded_at = datetime.now(UTC)
    safe_content = (
        f"timestamp={recorded_at.isoformat()} source=live_monitor_retest "
        "service_endpoint_match=true result=masked_only "
        "phone_masked=[MASKED] wallet_id_masked=[MASKED]\n"
    ).encode("utf-8")
    evidence = ingestion_service.ingest_file(
        db,
        content=safe_content,
        file_name=f"live-retest-{uuid.uuid4().hex[:12]}.log",
        evidence_type=EvidenceType.FIXED_LOG,
        source_system="live_monitor_retest",
        linked_incident_id=incident_id,
        uploaded_by=actor_id,
    )
    audit_service.log_action(
        db,
        action="live_monitor_retest_evidence_recorded",
        target_type="evidence_file",
        target_id=evidence.evidence_id,
        details={
            "incident_id": incident_id,
            "retest_source": "live_monitor",
            "service_endpoint_match": True,
            "sensitive_value_still_appears": False,
        },
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return LiveMonitorRetestResponse(
        incident_id=incident_id,
        evidence_id=evidence.evidence_id,
        retest_source="Live Monitor retest event",
        service_endpoint_match=True,
        sensitive_value_still_appears=False,
        result="retest evidence recorded",
        explanation=(
            "A synthetic masked retest event was recorded for the incident service and endpoint. "
            "This is evidence for verification, not an automatic fix decision."
        ),
        next_action="Run fix verification after the required human review gate is satisfied.",
    )
