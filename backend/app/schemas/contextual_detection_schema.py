from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


ConfidenceLabel = Literal["possible", "probable", "validated", "rejected", "requires_human_review"]


class ContextualDetectionResult(BaseModel):
    taxonomy_code: str
    taxonomy_version: str
    category_group: str
    detection_method: str
    matched_alias: str | None = None
    context_score: float = Field(ge=0.0, le=1.0)
    format_validation_status: str
    source_context_status: str
    credential_status: str | None = None
    document_type: str | None = None
    masked_value: str
    value_fingerprint: str | None = None
    fingerprint_strategy: str
    confidence_label: ConfidenceLabel
    review_status: str = "pending"
    internal_only: bool
    customer_notification_allowed: bool
    restricted_roles: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class SyntheticDetectionPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    synthetic: Literal[True]
    fields: dict[str, Any] = Field(default_factory=dict, max_length=50)
    source_context: dict[str, str] = Field(default_factory=dict, max_length=20)


class SyntheticDetectionPreviewResponse(BaseModel):
    results: list[ContextualDetectionResult]
    total: int
    persisted: bool = False
    notice: str = "Synthetic preview only; detections are possible classifications and require review."

class SensitiveDataClassificationRead(BaseModel):
    classification_id: str | None = None
    incident_id: str | None = None
    detection_id: str | None = None
    evidence_id: str | None = None
    taxonomy_code: str
    taxonomy_version: str | None = None
    category_group: str | None = None
    detection_method: str | None = None
    context_score: float | None = None
    format_validation_status: str | None = None
    source_context_status: str | None = None
    credential_status: str | None = None
    document_type: str | None = None
    masked_value: str | None = None
    confidence_label: str | None = None
    review_status: str | None = None
    internal_only: bool = False
    customer_notification_allowed: bool = False
    restricted: bool = False
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class SensitiveDataClassificationListResponse(BaseModel):
    incident_id: str
    classifications: list[SensitiveDataClassificationRead]
    total: int
    restricted_information_present: bool = False
    restricted_message: str | None = None

