from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import Severity


class NormalizedEventCreate(BaseModel):
    event_id: str
    evidence_id: str
    timestamp: datetime
    source_type: str
    service_name: str | None = None
    endpoint: str | None = None
    release_version: str | None = None
    event_type: str | None = None
    raw_reference: str | None = None
    masked_message: str | None = None
    severity: Severity | None = None
    linked_incident_id: str | None = None


class NormalizedEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: str
    evidence_id: str
    timestamp: datetime
    source_type: str
    service_name: str | None
    endpoint: str | None
    release_version: str | None
    event_type: str | None
    raw_reference: str | None
    masked_message: str | None
    severity: Severity | None
    linked_incident_id: str | None
