from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ClassificationFact(BaseModel):
    classification_id: str
    taxonomy_code: str
    taxonomy_version: str
    category_group: str
    detection_id: str | None = None
    evidence_id: str | None = None
    normalized_event_id: str | None = None
    affected_subject_reference_id: str | None = None
    credential_status: str | None = None
    confidence_label: str
    internal_only: bool = False
    evidence_role: str = "original"


class ExposureProfileCandidate(BaseModel):
    profile_type: str
    rule_id: str
    rule_version: str
    severity: str
    privacy_harm_level: str
    internal_only: bool
    customer_notification_allowed: bool
    grouping_method: str
    grouping_confidence: str
    grouping_key: str
    supporting_classification_ids: list[str]
    supporting_detection_ids: list[str]
    supporting_evidence_ids: list[str]
    matched_category_codes: list[str]
    possible_harms: list[str]
    containment_recommendations: list[str]
    missing_information: list[str]
    limitations: list[str]
    explanation: str


class ExposureProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    profile_id: str
    incident_id: str
    profile_type: str
    rule_id: str
    taxonomy_version: str
    combination_ruleset_version: str
    severity: str
    privacy_harm_level: str
    internal_only: bool
    customer_notification_allowed: bool
    grouping_method: str
    grouping_confidence: str
    grouping_key: str
    affected_subject_reference_id: str | None
    supporting_detection_ids: list[str]
    supporting_evidence_ids: list[str]
    matched_rule_ids: list[str]
    possible_harms: list[str]
    containment_recommendations: list[str]
    missing_information: list[str]
    limitations: list[str]
    review_status: str
    is_current: bool
    created_at: datetime
    reviewed_at: datetime | None
    reviewed_by: int | None


class ExposureProfileListResponse(BaseModel):
    incident_id: str
    profiles: list[ExposureProfileRead]
    total: int
    restricted_information_present: bool = False
    restricted_message: str | None = None


class ExposureProfileReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(accepted|rejected)$")
    reason: str = Field(min_length=10, max_length=2000)


class ExposureProfileReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


class ExposureCombinationRuleRead(BaseModel):
    rule_id: str
    version: str
    profile_type: str
    severity: str
    internal_only: bool
    explanation_template: str


