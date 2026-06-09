"""Connector V1 ingest: privacy gate, idempotency, map into existing gateway ingest."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies.integration_auth_dependencies import IntegrationPrincipal
from app.models.enums import EvidenceType, ExposureDecision
from app.models.integration_event import IntegrationEvent
from app.schemas.connector_schema import (
    CONNECTOR_PRIVACY_REJECTED,
    ConnectorEventEnvelope,
    ConnectorEventType,
    ConnectorIngestResponse,
)
from app.schemas.integration_schema import IntegrationEventIngestRequest
from app.services import audit_service, siem_import_service
from app.services.sensitive_exposure_engine import analyse

_SKEW = timedelta(hours=24)
_REJECT_DECISIONS = {
    ExposureDecision.UNSAFE_EXPOSURE.value,
    ExposureDecision.UNCERTAIN.value,
}
_TYPE_SOURCE = {
    ConnectorEventType.RUNTIME_EVENT: "api_log",
    ConnectorEventType.RUNTIME_EXPOSURE: "api_log",
    ConnectorEventType.WAZUH_ALERT: "siem_alert",
    ConnectorEventType.GITHUB_RUN: "cicd_event",
}
_TYPE_EVIDENCE = {
    ConnectorEventType.RUNTIME_EVENT: EvidenceType.RUNTIME_LOG,
    ConnectorEventType.RUNTIME_EXPOSURE: EvidenceType.RUNTIME_LOG,
    ConnectorEventType.WAZUH_ALERT: EvidenceType.SIEM_ALERT,
    ConnectorEventType.GITHUB_RUN: EvidenceType.DEPLOYMENT_LOG,
}
_TYPE_COLLECTOR = {
    ConnectorEventType.RUNTIME_EVENT: ("privacytrace_runtime", "1"),
    ConnectorEventType.RUNTIME_EXPOSURE: ("privacytrace_runtime", "1"),
    ConnectorEventType.WAZUH_ALERT: ("custom-privacytrace", "1"),
    ConnectorEventType.GITHUB_RUN: ("privacytrace_github_action", "1"),
}


class ConnectorPrivacyRejected(Exception):
    """Safe-only signal that residual secret content was present."""


def authenticated_source(principal: IntegrationPrincipal) -> str:
    if principal.source_name:
        return principal.source_name
    if principal.actor_id is not None:
        return f"user:{principal.actor_id}"
    return "jwt-ingest"


def _string_values(envelope: ConnectorEventEnvelope) -> list[str]:
    values: list[str] = [envelope.id, envelope.source, envelope.type.value]
    dumped = envelope.data.model_dump(exclude_none=True)
    for value in dumped.values():
        if isinstance(value, str):
            values.append(value)
    return values


def privacy_gate(envelope: ConnectorEventEnvelope) -> None:
    """Reject if any allowlisted string still looks like a residual secret.

    Already-masked / legitimate-processing findings are allowed. The offending
    value is never returned, logged, stored, or attached to the exception.
    """
    text = "\n".join(_string_values(envelope))
    findings = analyse(source_type="siem_import", text=text)
    for finding in findings:
        if finding.get("exposure_decision") in _REJECT_DECISIONS:
            raise ConnectorPrivacyRejected()
        if finding.get("safety_status") == "unsafe":
            raise ConnectorPrivacyRejected()


def _time_quality(event_time: datetime | None, received_at: datetime) -> str:
    if event_time is None:
        return "inferred"
    aware = event_time if event_time.tzinfo else event_time.replace(tzinfo=UTC)
    if abs(aware - received_at) > _SKEW:
        return "skewed"
    if event_time.tzinfo is None:
        return "reported_assumed_utc"
    return "reported_utc"


def _lookup_duplicate(db: Session, source_name: str, client_event_id: str) -> IntegrationEvent | None:
    return db.scalar(
        select(IntegrationEvent).where(
            IntegrationEvent.source_name == source_name,
            IntegrationEvent.client_event_id == client_event_id,
        )
    )


def _duplicate_response(row: IntegrationEvent) -> ConnectorIngestResponse:
    return ConnectorIngestResponse(
        event_id=row.integration_event_id,
        status="duplicate",
        evidence_id=row.evidence_reference,
        alert_id=row.linked_alert_id,
        incident_id=row.linked_incident_id,
        reason="duplicate",
    )


def ingest_connector_event(
    db: Session,
    envelope: ConnectorEventEnvelope,
    *,
    principal: IntegrationPrincipal,
) -> ConnectorIngestResponse:
    identity = authenticated_source(principal)
    existing = _lookup_duplicate(db, identity, envelope.id)
    if existing is not None:
        return _duplicate_response(existing)

    try:
        privacy_gate(envelope)
    except ConnectorPrivacyRejected:
        audit_service.log_action(
            db,
            action="connector_event_rejected",
            actor_id=principal.actor_id,
            actor_email=principal.actor_email,
            actor_role=principal.actor_role,
            target_type="connector_event",
            details={"reason": CONNECTOR_PRIVACY_REJECTED, "source_name": identity},
        )
        db.commit()
        return ConnectorIngestResponse(
            status="rejected",
            reason=CONNECTOR_PRIVACY_REJECTED,
        )

    data = envelope.data
    collector_name, collector_version = _TYPE_COLLECTOR[envelope.type]
    message = data.message_summary or f"Connector event {envelope.type.value}"
    req = IntegrationEventIngestRequest(
        source_name=identity,
        source_tool=collector_name,
        source_type=_TYPE_SOURCE[envelope.type],
        source_format="privacytrace_json",
        event_time=envelope.time,
        service_name=data.service,
        endpoint=data.route_template,
        environment=data.environment,
        event_type=envelope.type.value,
        sensitive_type=data.sensitive_type,
        masked_value=data.masked_value,
        severity=data.severity,
        message=message,
        trace_id=data.trace_id,
        tags=[],
        metadata={},
        payload=None,
    )
    received_at = datetime.now(UTC)
    outcome = siem_import_service.ingest_event(
        db,
        req,
        actor_id=principal.actor_id,
        actor_email=principal.actor_email,
        actor_role=principal.actor_role,
        source_name_override=identity,
        client_event_id=envelope.id,
        evidence_type=_TYPE_EVIDENCE[envelope.type],
        collector_name=collector_name,
        collector_version=collector_version,
        source_event_id=envelope.id,
        trace_id=data.trace_id,
        commit_sha=data.sha,
        source_time_quality_override=_time_quality(envelope.time, received_at),
        provenance_source_system=identity,
    )
    if outcome.status == "duplicate":
        canonical = outcome.canonical or {}
        return ConnectorIngestResponse(
            event_id=outcome.integration_event_id,
            status="duplicate",
            evidence_id=outcome.evidence_id or canonical.get("evidence_reference"),
            alert_id=outcome.alert_id or canonical.get("linked_alert_id"),
            incident_id=canonical.get("linked_incident_id"),
            reason="duplicate",
        )
    if outcome.status == "rejected":
        return ConnectorIngestResponse(
            status="rejected",
            reason=outcome.reason or "rejected",
        )
    canonical = outcome.canonical or {}
    return ConnectorIngestResponse(
        event_id=outcome.integration_event_id,
        status="accepted",
        evidence_id=outcome.evidence_id,
        alert_id=outcome.alert_id,
        incident_id=canonical.get("linked_incident_id"),
    )
