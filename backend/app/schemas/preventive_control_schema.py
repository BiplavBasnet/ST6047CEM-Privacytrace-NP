from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ControlType = Literal[
    "rego_policy",
    "semgrep_rule",
    "configuration_rule",
    "regression_test",
    "ci_check",
    "runtime_monitor",
    "manual_control",
    "documentation_change",
]


class PreventiveControlGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root_cause_id: str = Field(min_length=4, max_length=64)
    control_types: list[ControlType] = Field(default_factory=list, max_length=8)
    affected_component: str | None = Field(default=None, max_length=255)
    use_ai: bool = False


class PreventiveControlReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


class PreventiveControlReviewRequest(PreventiveControlReasonRequest):
    decision: Literal["accepted", "changes_required"]


class PreventiveControlImplementationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    implementation_reference: str = Field(min_length=4, max_length=512)
    remediation_action_id: str | None = Field(default=None, max_length=64)
    reason: str = Field(min_length=10, max_length=2000)


class PreventiveControlVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verification_method: str = Field(min_length=4, max_length=128)
    verification_result: str = Field(min_length=4, max_length=2000)
    passed: bool
    retest_evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    reason: str = Field(min_length=10, max_length=2000)


class PreventiveControlRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    control_id: str
    incident_id: str
    root_cause_id: str
    decision_record_id: str | None
    remediation_action_id: str | None
    control_type: str
    control_name: str
    control_description: str
    generated_content: str
    language: str | None
    status: str
    source: str
    generation_method: str
    ruleset_version: str
    requires_human_review: bool
    created_by: int | None
    reviewed_by: int | None
    reviewed_at: datetime | None
    approved_by: int | None
    approved_at: datetime | None
    rejection_reason: str | None
    implementation_reference: str | None
    implemented_by: int | None
    implemented_at: datetime | None
    verification_status: str
    verification_method: str | None
    verification_result: str | None
    verified_by: int | None
    verified_at: datetime | None
    failure_reason: str | None
    supersedes_control_id: str | None
    retired_by: int | None
    retired_at: datetime | None
    retirement_reason: str | None
    created_at: datetime
    updated_at: datetime


class PreventiveControlListResponse(BaseModel):
    incident_id: str
    controls: list[PreventiveControlRead]
    total: int
