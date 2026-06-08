from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import Severity


class DetectionCreate(BaseModel):
    detection_id: str
    incident_id: str
    evidence_id: str | None = None
    normalized_event_id: str | None = None
    sensitive_type: str
    masked_value: str
    confidence: float | None = None
    severity: Severity | None = None
    detector_name: str | None = None


class DetectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detection_id: str
    incident_id: str
    evidence_id: str | None
    normalized_event_id: str | None
    sensitive_type: str
    masked_value: str
    confidence: float | None
    severity: Severity | None
    detector_name: str | None
    created_at: datetime
