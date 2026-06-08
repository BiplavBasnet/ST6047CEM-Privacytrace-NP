from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import EvidenceType, ParsingStatus


class EvidenceFileCreate(BaseModel):
    evidence_id: str
    file_name: str
    evidence_type: EvidenceType
    source_system: str | None = None
    file_hash: str | None = None
    uploaded_by: int | None = None
    parsing_status: ParsingStatus = ParsingStatus.PENDING
    linked_incident_id: str | None = None


class EvidenceFileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: str
    file_name: str
    evidence_type: EvidenceType
    source_system: str | None
    file_hash: str | None
    uploaded_by: int | None
    upload_timestamp: datetime
    parsing_status: ParsingStatus
    linked_incident_id: str | None
    collector_name: str | None = None


class LoadSampleRequest(BaseModel):
    scenario: str = "scenario_1"
    uploaded_by: int | None = None


class LoadSampleResponse(BaseModel):
    scenario: str
    loaded: list[str]
    skipped: list[str]
    evidence_ids: list[str]


class EvidenceUploadResponse(BaseModel):
    message: str
    evidence: EvidenceFileRead


class ParseEvidenceResponse(BaseModel):
    evidence_id: str
    status: str
    event_count: int
    skipped: bool = False
    error: str | None = None


class ParseAllResponse(BaseModel):
    parsed: list[ParseEvidenceResponse]
    total_events: int


class DetectEvidenceResponse(BaseModel):
    evidence_id: str
    status: str
    detection_count: int = 0
    skipped: bool = False
    error: str | None = None
    warnings: list[str] = []


class DetectAllResponse(BaseModel):
    detected: list[DetectEvidenceResponse]
    total_detections: int
