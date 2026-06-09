"""Pydantic schemas for Live Privacy Monitor mode."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import json

from pydantic import BaseModel, ConfigDict, Field, model_validator

SUPPORTED_LIVE_SOURCE_FORMATS = (
    "generic_json",
    "syslog_like",
    "plain_text",
    "api_log_line",
    "ocsf_json",
    "ecs_json",
)

SUPPORTED_LIVE_INPUT_MODES = (
    "http_json",
    "syslog_like_text",
    "generic_api_log_line",
)


class LiveMonitorStartRequest(BaseModel):
    mode: str = Field(default="http_ingestion", min_length=1, max_length=64)
    source_name: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default="demo", max_length=64)
    safe_mode: bool = True


class LiveMonitorControlResponse(BaseModel):
    status: str
    message: str
    running: bool
    safe_mode: bool


class LiveMonitorStatusResponse(BaseModel):
    running: bool
    mode: str
    supported_input_modes: list[str]
    last_event_received_at: datetime | None = None
    event_count: int = 0
    alert_count: int
    last_alert_time: datetime | None = None
    safety_status: str


class LiveMonitorEventRequest(BaseModel):
    source_type: str = Field(default="api_log", min_length=1, max_length=128)
    source_name: str | None = Field(default=None, max_length=255)
    source_format: str = Field(default="generic_json", min_length=1, max_length=64)
    service_name: str | None = Field(default=None, max_length=255)
    endpoint: str | None = Field(default=None, max_length=512)
    environment: str | None = Field(default=None, max_length=64)
    timestamp: datetime | None = None
    message: str = Field(..., min_length=1, max_length=8000)
    # First-class correlation fields (also accepted via metadata aliases).
    trace_id: str | None = Field(default=None, max_length=128)
    request_id: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=128)
    deployment_version: str | None = Field(default=None, max_length=64)
    configuration_version: str | None = Field(default=None, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] | None = Field(default=None)

    @model_validator(mode="after")
    def validate_total_size(self):
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, default=str)
        if len(payload.encode("utf-8")) > 64 * 1024:
            raise ValueError("Live event payload exceeds the 64 KiB size limit.")
        return self


class LiveMonitorBatchRequest(BaseModel):
    events: list[LiveMonitorEventRequest] = Field(..., min_length=1, max_length=100)


class LiveAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    alert_time: datetime
    received_at: datetime
    source_type: str
    source_name: str | None = None
    source_format: str
    service_name: str | None = None
    endpoint: str | None = None
    environment: str | None = None
    severity: str
    status: str
    sensitive_types: list[str]
    masked_values: list[str]
    detection_ids: list[str]
    evidence_id: str | None = None
    linked_incident_id: str | None = None
    raw_event_hash: str
    safety_status: str
    alert_summary: str
    human_review_required: bool
    created_at: datetime
    updated_at: datetime
    first_seen: datetime
    last_seen: datetime
    repeat_count: int = 1
    ingestion_source: str = "live_monitor"
    missing_metadata: list[str] = Field(default_factory=list)
    correlation_recommendations: list[str] = Field(default_factory=list)
    evidence_strength: str = "limited"
    alert_group_key: str | None = None
    affected_trace_count: int | None = None
    trace_count_quality: str = "unavailable"
    first_source_event_time: datetime | None = None
    last_source_event_time: datetime | None = None
    source_time_quality: str = "inferred"
    source_time_inferred: bool = True
    source_timezone_name: str | None = None
    grouping_rule_version: str | None = None
    exposure_location: str | None = None
    confidence_score: float | None = None
    confidence_level: str | None = None


class LiveMonitorEventResponse(BaseModel):
    status: str
    safety_status: str
    alert_id: str | None = None
    alert: LiveAlertRead | None = None
    sensitive_types: list[str] = Field(default_factory=list)
    masked_values: list[str] = Field(default_factory=list)
    raw_event_hash: str | None = None
    reason: str | None = None
    message: str


class LiveMonitorBatchItemResponse(BaseModel):
    index: int
    status: str
    safety_status: str
    alert_id: str | None = None
    reason: str | None = None
    sensitive_types: list[str] = Field(default_factory=list)


class LiveMonitorBatchResponse(BaseModel):
    total: int
    alert_count: int
    no_alert_count: int
    rejected_count: int
    results: list[LiveMonitorBatchItemResponse]


class LiveAlertListResponse(BaseModel):
    alerts: list[LiveAlertRead]
    total: int


class LiveAlertIncidentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str = Field(..., pattern="^(create_new|link_existing)$")
    incident_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_mode_fields(self):
        if self.mode == "link_existing" and not self.incident_id:
            raise ValueError("incident_id is required when linking an existing incident.")
        if self.mode == "create_new" and self.incident_id is not None:
            raise ValueError("incident_id must not be supplied when creating a new incident.")
        return self


class LiveAlertIncidentResponse(BaseModel):
    alert_id: str
    incident_id: str
    status: str
    message: str


class LiveAlertDismissRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=10, max_length=1000)


class LiveAlertDismissResponse(BaseModel):
    alert_id: str
    status: str
    message: str


class LiveMonitorRetestRequest(BaseModel):
    """Reserved for future safe retest options; the current event is synthetic."""

    model_config = ConfigDict(extra="forbid")


class LiveMonitorRetestResponse(BaseModel):
    incident_id: str
    evidence_id: str
    retest_source: str
    service_endpoint_match: bool
    sensitive_value_still_appears: bool
    result: str
    explanation: str
    next_action: str
