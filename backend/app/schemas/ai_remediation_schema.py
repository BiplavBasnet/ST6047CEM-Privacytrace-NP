"""Schemas for the AI Remediation Assistant."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AIRemediationStatusResponse(BaseModel):
    enabled: bool
    provider_configured: bool
    model: str | None = None
    safety_gateway_enabled: bool = True
    message: str


class AIRemediationSuggestionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    suggestion_id: str
    incident_id: str
    requested_by_user_id: int | None = None
    requested_at: datetime
    ai_provider: str | None = None
    ai_model: str | None = None
    input_safety_status: str
    output_safety_status: str
    status: str
    masked_input_summary_hash: str
    suggestion_summary: str | None = None
    likely_issue_area: str | None = None
    remediation_actions: list[str] = Field(default_factory=list)
    code_or_config_areas: list[str] = Field(default_factory=list)
    suggested_tests: list[str] = Field(default_factory=list)
    retest_evidence_required: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    human_review_required: bool
    reviewer_decision: str | None = None
    reviewer_notes: str | None = None
    accepted_as_remediation_action_id: str | None = None
    created_at: datetime
    updated_at: datetime


class AIRemediationSuggestResponse(BaseModel):
    suggestion: AIRemediationSuggestionRead
    message: str


class AIRemediationSuggestionListResponse(BaseModel):
    incident_id: str
    suggestions: list[AIRemediationSuggestionRead]
    total: int


class AIRemediationAcceptRequest(BaseModel):
    reviewer_notes: str | None = Field(default=None, max_length=2000)
    create_remediation_action: bool = False


class AIRemediationEditRequest(BaseModel):
    edited_remediation_actions: list[str] = Field(..., min_length=1, max_length=20)
    reviewer_notes: str | None = Field(default=None, max_length=2000)


class AIRemediationRejectRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=2000)


class AIRemediationDecisionResponse(BaseModel):
    suggestion_id: str
    status: str
    reviewer_decision: str
    accepted_as_remediation_action_id: str | None = None
    message: str


class DiagnosisReviewRequest(BaseModel):
    decision: str = Field(
        ...,
        description="accept | accept_with_edits | reject | request_more_evidence",
        max_length=64,
    )
    notes: str | None = Field(default=None, max_length=4000)
    edited_primary: dict | None = None
    create_remediation_action: bool = False


class DiagnosisReviewResponse(BaseModel):
    diagnosis_id: str
    status: str
    reviewer_decision: str | None = None
    remediation_action_id: str | None = None
    message: str


class ControlledPatchRequest(BaseModel):
    diagnosis_id: str


class SandboxTestRequest(BaseModel):
    profile: str = Field(..., min_length=1, max_length=64)
    remediation_action_id: str = Field(..., min_length=1, max_length=64)
    implementation_id: str = Field(..., min_length=1, max_length=64)
    patch_proposal_id: str | None = Field(default=None, max_length=64)
