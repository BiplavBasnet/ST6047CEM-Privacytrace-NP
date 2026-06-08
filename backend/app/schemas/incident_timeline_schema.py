from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


ActorType = Literal["user", "system", "integration", "unknown"]
TimeStatus = Literal["observed", "delayed_ingestion", "estimated", "unknown_original_time"]


class IncidentTimelineEventRead(BaseModel):
    id: str
    incident_id: str
    event_type: str
    lifecycle_stage: str
    event_timestamp: datetime
    recorded_timestamp: datetime
    time_status: TimeStatus
    actor_type: ActorType = "unknown"
    actor_id: str | None = None
    source_type: str
    source_id: str
    evidence_ids: list[str] = Field(default_factory=list)
    status_before: str | None = None
    status_after: str | None = None
    reason: str | None = None
    summary: str
    metadata: dict = Field(default_factory=dict)
    integrity_record_id: str | None = None
    integrity_status: str = "not_yet_verified"


class IncidentTimelineResponse(BaseModel):
    incident_id: str
    events: list[IncidentTimelineEventRead]
    total: int
    limitations: list[str] = Field(default_factory=list)
