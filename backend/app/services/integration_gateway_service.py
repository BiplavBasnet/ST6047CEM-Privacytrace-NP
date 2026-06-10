"""Status, schema, snippets, and synthetic helpers for the integration gateway."""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.schemas.integration_schema import (
    ACCEPTED_SOURCE_TYPES,
    INTEGRATION_SCHEMA_VERSION,
    IntegrationGatewayStatusResponse,
    IntegrationSchemaResponse,
    IntegrationSnippetsResponse,
)
from app.services import audit_service, integration_mapping_service, integration_service, live_monitor_config_service


def get_status(db: Session) -> IntegrationGatewayStatusResponse:
    ingested = list(
        db.scalars(select(AuditLog).where(AuditLog.action == "integration_event_ingested")).all()
    )
    accepted_count = len(ingested)
    # ponytail: decrypt audit details in-process; SQL JSONB cannot see encrypted payloads.
    alerts_count = sum(
        1
        for row in ingested
        if audit_service.resolve_audit_details(row).get("alert_created")
    )
    latest = db.scalar(
        select(AuditLog)
        .where(
            AuditLog.action.in_(
                ("integration_event_ingested", "integration_event_rejected")
            )
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(1)
    )
    state = live_monitor_config_service.get_state(db)
    details = audit_service.resolve_audit_details(latest) if latest else {}
    latest_error = (
        "The most recent gateway event was rejected safely."
        if latest and latest.action == "integration_event_rejected"
        else None
    )
    return IntegrationGatewayStatusResponse(
        gateway_enabled=bool(
            get_settings().integration_gateway_enabled and state.running
        ),
        accepted_event_types=list(ACCEPTED_SOURCE_TYPES),
        last_event_received_at=latest.timestamp if latest else None,
        source_name=details.get("source_name"),
        events_received_count=int(accepted_count),
        alerts_created_count=int(alerts_count),
        latest_error=latest_error,
        safety_status="safe",
    )


def get_schema() -> IntegrationSchemaResponse:
    return IntegrationSchemaResponse(
        schema_version=INTEGRATION_SCHEMA_VERSION,
        endpoint="/integrations/events",
        required_fields=["source_name", "message"],
        optional_fields=[
            "source_type",
            "source_format",
            "service_name",
            "endpoint",
            "environment",
            "event_time",
            "severity",
            "metadata",
        ],
        accepted_source_types=list(ACCEPTED_SOURCE_TYPES),
        accepted_source_formats=list(
            integration_mapping_service.SUPPORTED_INBOUND_FORMATS
        ),
        example=integration_service.safe_payload_example(),
    )


def get_snippets() -> IntegrationSnippetsResponse:
    payload = json.dumps(integration_service.safe_payload_example(), indent=2)
    compact = json.dumps(integration_service.safe_payload_example())
    return IntegrationSnippetsResponse(
        curl=(
            "curl -sS -X POST http://127.0.0.1:8000/integrations/events \\\n"
            '  -H "Authorization: Bearer $PRIVACYTRACE_TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            f"  -d '{compact}'"
        ),
        python=(
            "import os\nimport requests\n\n"
            "response = requests.post(\n"
            '    "http://127.0.0.1:8000/integrations/events",\n'
            '    headers={"Authorization": "Bearer " + os.environ["PRIVACYTRACE_TOKEN"]},\n'
            f"    json={repr(integration_service.safe_payload_example())},\n"
            "    timeout=15,\n)\nresponse.raise_for_status()"
        ),
        node=(
            "const response = await fetch(\"http://127.0.0.1:8000/integrations/events\", {\n"
            '  method: "POST",\n'
            '  headers: { "Authorization": "Bearer " + process.env.PRIVACYTRACE_TOKEN, "Content-Type": "application/json" },\n'
            f"  body: JSON.stringify({compact})\n"
            "});\nif (!response.ok) throw new Error(\"Gateway request failed\");"
        ),
        docker_log_forwarder=(
            "docker build -t privacytrace-log-forwarder tools/log-forwarder\n"
            "docker run --rm --env-file tools/log-forwarder/.env "
            "-v /path/to/logs:/logs:ro privacytrace-log-forwarder"
        ),
        generic_webhook=(
            "POST /integrations/events\n"
            "Authorization: Bearer $PRIVACYTRACE_TOKEN\n"
            "Content-Type: application/json\n\n"
            f"{payload}"
        ),
        siem_alert_export=(
            "curl -sS -X POST http://127.0.0.1:8000/integrations/events \\\n"
            '  -H "Authorization: Bearer $PRIVACYTRACE_TOKEN" \\\n'
            '  -H "Content-Type: application/json" \\\n'
            "  -d '{\"source_name\":\"alert-tool\",\"source_type\":"
            "\"siem_alert\",\"message\":\"Synthetic masked alert\","
            "\"metadata\":{\"trace_id\":\"trace-demo-001\"}}'"
        ),
    )
