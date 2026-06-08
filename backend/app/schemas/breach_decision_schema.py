from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


DecisionStatus = Literal["draft", "changes_required", "reviewed", "approved", "superseded"]
BreachDetermination = Literal["suspected", "confirmed", "not_breach", "insufficient_evidence"]
FactorDirection = Literal["increases", "reduces", "neutral", "unknown"]


class BreachDecisionFactorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    factor_type: str = Field(min_length=1, max_length=64)
    factor_code: str = Field(min_length=1, max_length=128)
    factor_label: str = Field(min_length=1, max_length=255)
    direction: FactorDirection
    score_contribution: float
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    reason: str = Field(min_length=5, max_length=2000)
    source: str = Field(min_length=1, max_length=64)
    method_version: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1, max_length=64)


class BreachDecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_id: str = Field(min_length=1, max_length=64)
    breach_determination: BreachDetermination = "insufficient_evidence"
    assessment_method_version: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1, max_length=64)
    root_cause_ruleset_version: str = Field(min_length=1, max_length=128)
    taxonomy_version: str | None = Field(default=None, max_length=64)
    combination_ruleset_version: str | None = Field(default=None, max_length=64)
    input_evidence_ids: list[str] = Field(default_factory=list, max_length=500)
    affected_data_categories: list[str] = Field(default_factory=list, max_length=100)
    affected_subject_count: int | None = Field(default=None, ge=0)
    affected_subject_count_status: Literal["unknown", "estimated", "confirmed"] = "unknown"
    severity_inputs: dict = Field(default_factory=dict)
    privacy_harm_inputs: dict = Field(default_factory=dict)
    root_cause_summary: dict = Field(default_factory=dict)
    severity_result: dict = Field(default_factory=dict)
    privacy_harm_result: dict = Field(default_factory=dict)
    alert_recommendation: dict = Field(default_factory=dict)
    containment_recommendations: list[dict] = Field(default_factory=list, max_length=100)
    customer_notification_recommendation: dict = Field(default_factory=dict)
    missing_information: list[str] = Field(default_factory=list, max_length=100)
    uncertainties: list[str] = Field(default_factory=list, max_length=100)
    limitations: list[str] = Field(default_factory=list, max_length=100)
    exposure_profile_ids: list[str] = Field(default_factory=list, max_length=100)
    internal_only_restrictions: list[str] = Field(default_factory=list, max_length=100)
    human_override_present: bool = False
    human_override_reason: str | None = Field(default=None, max_length=2000)
    factors: list[BreachDecisionFactorInput] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def validate_override(self):
        if self.human_override_present and not (self.human_override_reason or "").strip():
            raise ValueError("A human override requires a reason.")
        return self


class BreachDecisionReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["accepted", "changes_required"]
    reason: str = Field(min_length=10, max_length=2000)
    factor_review_statuses: dict[int, Literal["accepted", "changes_required"]] = Field(default_factory=dict)


class BreachDecisionApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


class BreachDecisionSupersedeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)
    replacement: BreachDecisionCreate


class BreachDecisionFactorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    decision_record_id: str
    factor_type: str
    factor_code: str
    factor_label: str
    direction: str
    score_contribution: float
    evidence_ids: list[str]
    reason: str
    source: str
    method_version: str
    policy_version: str
    review_status: str
    created_at: datetime


class BreachDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    decision_id: str
    incident_id: str
    assessment_id: str
    decision_version: int
    status: str
    breach_determination: str
    assessment_method_version: str
    policy_version: str
    root_cause_ruleset_version: str
    taxonomy_version: str | None
    combination_ruleset_version: str | None
    input_evidence_ids: list[str]
    affected_data_categories: list[str]
    affected_subject_count: int | None
    affected_subject_count_status: str
    severity_inputs: dict
    privacy_harm_inputs: dict
    root_cause_summary: dict
    severity_result: dict
    privacy_harm_result: dict
    alert_recommendation: dict
    containment_recommendations: list
    customer_notification_recommendation: dict
    missing_information: list[str]
    uncertainties: list[str]
    limitations: list[str]
    exposure_profile_ids: list[str]
    internal_only_restrictions: list[str]
    human_override_present: bool
    human_override_reason: str | None
    created_by: int | None
    reviewed_by: int | None
    approved_by: int | None
    created_at: datetime
    reviewed_at: datetime | None
    approved_at: datetime | None
    supersedes_record_id: str | None
    superseded_by_record_id: str | None
    integrity_record_id: str | None
    factors: list[BreachDecisionFactorRead] = Field(default_factory=list)


class BreachDecisionListResponse(BaseModel):
    decisions: list[BreachDecisionRead]
    total: int


class BreachDecisionDifferenceResponse(BaseModel):
    decision_id: str
    compared_to_decision_id: str | None
    added_evidence: list[str] = Field(default_factory=list)
    removed_evidence: list[str] = Field(default_factory=list)
    changed_factors: list[dict] = Field(default_factory=list)
    changed_fields: dict[str, dict] = Field(default_factory=dict)
