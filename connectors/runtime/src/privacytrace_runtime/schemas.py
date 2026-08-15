"""CloudEvents-inspired connector ingest contract.

Keep in sync with backend/app/schemas/connector_schema.py.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_EVENT_BYTES = 64 * 1024

CONNECTOR_SCHEMA_VERSION = "1.0"
CONNECTOR_PRIVACY_REJECTED = "CONNECTOR_PAYLOAD_PRIVACY_REJECTED"


class ConnectorEventType(StrEnum):
    RUNTIME_EVENT = "np.privacytrace.runtime.event.v1"
    RUNTIME_EXPOSURE = "np.privacytrace.runtime.exposure.v1"
    WAZUH_ALERT = "np.privacytrace.wazuh.alert.v1"
    GITHUB_RUN = "np.privacytrace.cicd.github.run.v1"


class ConnectorEventData(BaseModel):
    """Allowlisted connector payload. No full URL, query, headers, body, or full_log."""

    model_config = ConfigDict(extra="forbid")

    service: str | None = Field(default=None, min_length=1, max_length=255)
    route_template: str | None = Field(default=None, min_length=1, max_length=512)
    method: str | None = Field(default=None, min_length=1, max_length=16)
    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    trace_id: str | None = Field(default=None, min_length=1, max_length=128)
    component: str | None = Field(default=None, min_length=1, max_length=128)
    deployment: str | None = Field(default=None, min_length=1, max_length=128)
    environment: str | None = Field(default=None, min_length=1, max_length=64)
    severity: str | None = Field(default=None, min_length=1, max_length=32)
    sensitive_type: str | None = Field(default=None, min_length=1, max_length=128)
    masked_value: str | None = Field(default=None, min_length=1, max_length=512)
    message_summary: str | None = Field(default=None, min_length=1, max_length=500)
    rule_id: str | None = Field(default=None, min_length=1, max_length=64)
    rule_group: str | None = Field(default=None, min_length=1, max_length=128)
    rule_level: int | None = Field(default=None, ge=0, le=16)
    repo: str | None = Field(default=None, min_length=1, max_length=255)
    sha: str | None = Field(default=None, min_length=1, max_length=64)
    run_id: str | None = Field(default=None, min_length=1, max_length=64)
    workflow: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("route_template")
    @classmethod
    def route_is_template(cls, value: str | None) -> str | None:
        if value is None:
            return value
        lowered = value.lower()
        if "?" in value or "#" in value or lowered.startswith("http://") or lowered.startswith("https://"):
            raise ValueError("route_template must be a path template, not a full URL.")
        return value


class ConnectorEventEnvelope(BaseModel):
    """CloudEvents-inspired envelope. extra=forbid on the whole object."""

    model_config = ConfigDict(extra="forbid")

    specversion: Literal["1.0"]
    id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=2048)
    type: ConnectorEventType
    time: datetime | None = None
    datacontenttype: Literal["application/json"] = "application/json"
    data: ConnectorEventData

    @field_validator("id")
    @classmethod
    def id_is_token(cls, value: str) -> str:
        if any(ch.isspace() for ch in value):
            raise ValueError("id must not contain whitespace.")
        return value

    @field_validator("source")
    @classmethod
    def source_is_uri_ref(cls, value: str) -> str:
        if any(ch.isspace() for ch in value) or "?" in value or "#" in value:
            raise ValueError("source must be a URI-reference without query or fragment.")
        return value

    @model_validator(mode="after")
    def enforce_size(self) -> ConnectorEventEnvelope:
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True, default=str)
        if len(blob.encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError("Connector event exceeds the 64 KiB size limit.")
        return self


class ConnectorIngestResponse(BaseModel):
    event_id: str | None = None
    status: Literal["accepted", "duplicate", "rejected"]
    evidence_id: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None
    reason: str | None = None


def connector_json_schema() -> dict[str, Any]:
    return ConnectorEventEnvelope.model_json_schema()
