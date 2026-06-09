"""Pydantic schemas for Phase 11.8 universal SIEM/SOC integration layer.

The PrivacyTraceIntegrationEvent is the canonical, vendor-neutral
representation used internally. Inbound adapters (OCSF, ECS, Splunk HEC,
generic) map external payloads into this schema before any safety
validation or persistence. Outbound exporters map incident summaries
into the same vendor-neutral target formats.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import json

from pydantic import BaseModel, ConfigDict, Field, model_validator

INTEGRATION_SCHEMA_VERSION = "1.0"

SUPPORTED_INBOUND_FORMATS = (
    "privacytrace_json",
    "ocsf_json",
    "ecs_json",
    "splunk_hec_json",
    "generic_json",
)

SUPPORTED_OUTBOUND_FORMATS = (
    "privacytrace_json",
    "ocsf_json",
    "ecs_json",
    "splunk_hec_json",
    "cef_like",
    "leef_like",
    "rfc5424_syslog_like",
)

ACCEPTED_SOURCE_TYPES = (
    "api_log",
    "application_log",
    "syslog",
    "siem_alert",
    "webhook_alert",
    "transaction_event",
    "cicd_event",
    "deployment_event",
    "scanner_finding",
    "retest_event",
    "custom",
)


class IntegrationEventIngestRequest(BaseModel):
    """Inbound request body for /integrations/events.

    `payload` carries the raw vendor JSON for OCSF/ECS/Splunk HEC/generic
    formats; for privacytrace_json the top-level fields are used directly.
    """

    source_name: str | None = Field(default=None, min_length=1, max_length=255)
    source_tool: str | None = Field(default=None, min_length=1, max_length=128)
    source_type: str | None = Field(default=None, max_length=64)
    source_format: str = Field(default="generic_json", min_length=1, max_length=64)
    external_alert_id: str | None = Field(None, max_length=128)
    external_incident_id: str | None = Field(None, max_length=128)
    event_time: datetime | None = None
    service_name: str | None = Field(None, max_length=255)
    endpoint: str | None = Field(None, max_length=512)
    environment: str | None = Field(None, max_length=64)
    event_type: str | None = Field(None, max_length=128)
    sensitive_type: str | None = Field(None, max_length=128)
    masked_value: str | None = Field(None, max_length=512)
    severity: str | None = Field(None, max_length=32)
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    message: str | None = Field(None, max_length=4000)
    evidence_reference: str | None = Field(None, max_length=255)
    source_ip: str | None = Field(None, max_length=64)
    destination_ip: str | None = Field(None, max_length=64)
    user_or_actor: str | None = Field(None, max_length=255)
    trace_id: str | None = Field(None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)
    linked_incident_id: str | None = Field(None, max_length=64)
    payload: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional vendor-format payload (OCSF, ECS, Splunk HEC, generic). "
            "Sensitive values are masked before persistence or display. "
            "Raw payload is never returned."
        ),
    )

    @model_validator(mode="after")
    def validate_total_size(self):
        resolved_name = (self.source_name or self.source_tool or "").strip()
        if not resolved_name:
            raise ValueError("source_name is required.")
        self.source_name = resolved_name
        self.source_tool = (self.source_tool or resolved_name)[:128]
        if not (self.message and self.message.strip()) and not self.payload:
            raise ValueError("message is required when no vendor payload is supplied.")
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, default=str)
        if len(payload.encode("utf-8")) > 64 * 1024:
            raise ValueError("Integration event payload exceeds the 64 KiB size limit.")
        if any(len(str(tag)) > 128 for tag in self.tags):
            raise ValueError("Integration event tags must not exceed 128 characters.")
        return self


class IntegrationEventBatchRequest(BaseModel):
    events: list[IntegrationEventIngestRequest] = Field(
        ...,
        min_length=1,
        max_length=100,
    )


class IntegrationEventSafeRead(BaseModel):
    """Safe metadata view of an ingested integration event.

    `raw_payload_hash` is preserved for traceability; the raw payload
    itself is never returned by the API.
    """

    model_config = ConfigDict(from_attributes=True)

    schema_version: str = INTEGRATION_SCHEMA_VERSION
    integration_event_id: str
    event_id: str
    source_name: str
    source_tool: str
    source_type: str
    source_format: str
    external_alert_id: str | None = None
    external_incident_id: str | None = None
    event_time: datetime | None = None
    received_at: datetime
    service_name: str | None = None
    endpoint: str | None = None
    environment: str | None = None
    event_type: str | None = None
    sensitive_type: str | None = None
    masked_value: str | None = None
    severity: str | None = None
    confidence: float | None = None
    message: str | None = None
    message_summary: str
    evidence_reference: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user_or_actor: str | None = None
    trace_id: str | None = None
    trace_fingerprint: str | None = None
    correlation_fingerprint_method: str | None = None
    correlation_fingerprint_version: str | None = None
    source_time_quality: str = "inferred"
    source_time_inferred: bool = True
    source_timezone_name: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw_payload_hash: str | None = None
    safety_status: str
    sensitive_types: list[str] = Field(default_factory=list)
    masked_values: list[str] = Field(default_factory=list)
    correlation_keys: dict[str, Any] = Field(default_factory=dict)
    linked_alert_id: str | None = None
    linked_incident_id: str | None = None
    missing_metadata: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    correlation_strength: str = "limited"
    warning: str | None = None


class IntegrationEventIngestResponse(BaseModel):
    status: str
    integration_event_id: str | None = None
    safety_status: str
    reason: str | None = None
    event: IntegrationEventSafeRead | None = None
    alert_created: bool = False
    alert_id: str | None = None
    missing_metadata: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class IntegrationBatchItemResult(BaseModel):
    index: int
    status: str
    integration_event_id: str | None = None
    safety_status: str
    reason: str | None = None
    external_alert_id: str | None = None
    alert_created: bool = False
    alert_id: str | None = None


class IntegrationBatchResponse(BaseModel):
    total: int
    accepted: int
    rejected: int
    results: list[IntegrationBatchItemResult]


class IntegrationFormatInfo(BaseModel):
    format_id: str
    direction: str
    title: str
    description: str


class IntegrationFormatsResponse(BaseModel):
    inbound: list[IntegrationFormatInfo]
    outbound: list[IntegrationFormatInfo]


class IntegrationIncidentExportResponse(BaseModel):
    """Outbound SOC export response.

    The exported representation is returned under ``export_body`` rather
    than ``body`` because the frontend safety sanitizer strips any field
    literally named ``body`` from API responses (defence-in-depth against
    raw request/response bodies leaking into the UI). The content under
    ``export_body`` is already validated by ``report_safety_service`` on
    the server before it is returned, and is sanitized again on the client.
    """

    incident_id: str
    format: str
    content_type: str
    export_body: str | dict[str, Any]
    generated_at: datetime


class IntegrationGatewayStatusResponse(BaseModel):
    gateway_enabled: bool
    accepted_event_types: list[str]
    last_event_received_at: datetime | None = None
    source_name: str | None = None
    events_received_count: int
    alerts_created_count: int
    latest_error: str | None = None
    safety_status: str


class IntegrationSchemaResponse(BaseModel):
    schema_version: str
    endpoint: str
    required_fields: list[str]
    optional_fields: list[str]
    accepted_source_types: list[str]
    accepted_source_formats: list[str]
    example: dict[str, Any]


class IntegrationSnippetsResponse(BaseModel):
    curl: str
    python: str
    node: str
    docker_log_forwarder: str
    generic_webhook: str
    siem_alert_export: str


class IntegrationValidationResponse(BaseModel):
    valid: bool
    detected_source_type: str
    required_fields_missing: list[str] = Field(default_factory=list)
    safety_status: str
    would_create_alert: bool
    missing_metadata: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    reason: str | None = None


class IntegrationTokenCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    source_name: str = Field(min_length=1, max_length=255)


class IntegrationTokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    token_id: str
    name: str
    source_name: str
    token_prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    is_active: bool


class IntegrationTokenCreatedResponse(IntegrationTokenRead):
    token: str


class IntegrationTokenListResponse(BaseModel):
    tokens: list[IntegrationTokenRead]
    total: int


class IntegrationTokenRevokeResponse(BaseModel):
    token_id: str
    is_active: bool
    message: str
