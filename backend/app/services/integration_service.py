"""Phase 11.8 high-level orchestrator for the universal integration layer.

This module exposes thin coordination helpers for the router – the heavy
work happens in :mod:`siem_import_service`,
:mod:`siem_export_service` and the validation/mapping helpers.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.schemas.integration_schema import (
    IntegrationBatchItemResult,
    IntegrationBatchResponse,
    IntegrationEventIngestRequest,
    IntegrationEventIngestResponse,
    IntegrationEventSafeRead,
    IntegrationFormatInfo,
    IntegrationFormatsResponse,
)
from app.services import (
    audit_service,
    integration_mapping_service,
    siem_export_service,
    siem_import_service,
)
from app.services.integration_mapping_service import UnsupportedSourceFormatError


def ingest_single_event(
    db: Session,
    req: IntegrationEventIngestRequest,
    *,
    actor_id: int | None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    source_name_override: str | None = None,
) -> IntegrationEventIngestResponse:
    outcome = siem_import_service.ingest_event(
        db,
        req,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        source_name_override=source_name_override,
    )
    if outcome.status == "rejected":
        return IntegrationEventIngestResponse(
            status="rejected",
            safety_status="rejected",
            reason=outcome.reason,
            missing_metadata=outcome.missing_metadata or [],
            recommendations=outcome.recommendations or [],
        )
    safe_view = (
        IntegrationEventSafeRead(**outcome.canonical) if outcome.canonical else None
    )
    return IntegrationEventIngestResponse(
        status="accepted",
        safety_status="safe",
        integration_event_id=outcome.integration_event_id,
        event=safe_view,
        alert_created=outcome.alert_created,
        alert_id=outcome.alert_id,
        missing_metadata=outcome.missing_metadata or [],
        recommendations=outcome.recommendations or [],
    )


def ingest_batch(
    db: Session,
    events: list[IntegrationEventIngestRequest],
    *,
    actor_id: int | None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    source_name_override: str | None = None,
) -> IntegrationBatchResponse:
    results: list[IntegrationBatchItemResult] = []
    accepted = 0
    rejected = 0
    accepted_ids: list[str] = []

    for index, item in enumerate(events):
        try:
            outcome = siem_import_service.ingest_event(
                db,
                item,
                actor_id=actor_id,
                actor_email=actor_email,
                actor_role=actor_role,
                source_name_override=source_name_override,
            )
        except UnsupportedSourceFormatError as exc:
            rejected += 1
            results.append(
                IntegrationBatchItemResult(
                    index=index,
                    status="rejected",
                    safety_status="rejected",
                    reason=str(exc),
                    external_alert_id=item.external_alert_id,
                    alert_created=outcome.alert_created,
                    alert_id=outcome.alert_id,
                )
            )
            continue

        if outcome.status == "accepted":
            accepted += 1
            if outcome.integration_event_id:
                accepted_ids.append(outcome.integration_event_id)
            results.append(
                IntegrationBatchItemResult(
                    index=index,
                    status="accepted",
                    safety_status="safe",
                    integration_event_id=outcome.integration_event_id,
                    external_alert_id=item.external_alert_id,
                )
            )
        else:
            rejected += 1
            results.append(
                IntegrationBatchItemResult(
                    index=index,
                    status="rejected",
                    safety_status="rejected",
                    reason=outcome.reason,
                    external_alert_id=item.external_alert_id,
                )
            )

    audit_service.log_action(
        db,
        action="integration_batch_ingested",
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="integration_batch",
        target_id=None,
        details={
            "total": len(events),
            "accepted": accepted,
            "rejected": rejected,
            "accepted_ids": accepted_ids[:50],
        },
    )
    db.commit()

    return IntegrationBatchResponse(
        total=len(events),
        accepted=accepted,
        rejected=rejected,
        results=results,
    )


def get_event_metadata(db: Session, integration_event_id: str) -> IntegrationEventSafeRead | None:
    return siem_import_service.get_safe_event_read(db, integration_event_id)


def list_formats() -> IntegrationFormatsResponse:
    inbound_descriptions = {
        "privacytrace_json": (
            "Canonical PrivacyTrace JSON. Send safe/masked fields as defined "
            "in the request schema."
        ),
        "ocsf_json": (
            "Open Cybersecurity Schema Framework style payload. Basic, "
            "adapter-based mapping (not vendor-certified)."
        ),
        "ecs_json": (
            "Elastic Common Schema style payload. Basic, adapter-based "
            "mapping (not vendor-certified)."
        ),
        "splunk_hec_json": (
            "Splunk HTTP Event Collector style payload. Basic, "
            "adapter-based mapping (not vendor-certified)."
        ),
        "generic_json": (
            "Generic JSON payload with flat top-level fields matching the "
            "canonical schema names."
        ),
    }
    inbound = [
        IntegrationFormatInfo(
            format_id=fmt,
            direction="inbound",
            title=fmt.replace("_", " ").upper(),
            description=inbound_descriptions[fmt],
        )
        for fmt in integration_mapping_service.SUPPORTED_INBOUND_FORMATS
    ]
    outbound = [
        IntegrationFormatInfo(**entry)
        for entry in siem_export_service.list_supported_formats()
    ]
    return IntegrationFormatsResponse(inbound=inbound, outbound=outbound)


def safe_payload_example() -> dict[str, Any]:
    """Synthetic universal event used by schema, snippets, and the frontend."""
    return {
        "source_name": "wallet-service",
        "source_type": "api_log",
        "source_format": "generic_json",
        "environment": "staging",
        "service_name": "wallet-service",
        "endpoint": "/wallet/transfer",
        "event_time": "2026-07-13T10:30:00Z",
        "severity": "info",
        "message": "Synthetic integration test event",
        "metadata": {
            "deployment_version": "v1.4.2",
            "trace_id": "trace-demo-001",
        },
    }
