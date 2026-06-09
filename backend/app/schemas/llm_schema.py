from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SafetyNotes(BaseModel):
    uses_masked_evidence_only: bool = True
    contains_raw_sensitive_values: bool = False
    contains_overclaiming: bool = False
    human_review_required: bool = True


class AlternativeHypothesis(BaseModel):
    hypothesis: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    confidence_note: str = ""


class InvestigationOutput(BaseModel):
    incident_summary: str
    likely_cause_explanation: str
    supporting_evidence_summary: str
    alternative_hypotheses: list[AlternativeHypothesis] = Field(default_factory=list)
    missing_evidence_questions: list[str] = Field(default_factory=list)
    recommended_fix_draft: str
    fix_verification_checklist: list[str] = Field(default_factory=list)
    human_review_note: str
    safety_notes: SafetyNotes = Field(default_factory=SafetyNotes)


class ExplainIncidentRequest(BaseModel):
    provider: Literal["ollama", "template"] | None = None
    model: str | None = None
    force_template: bool = False


class ExplainIncidentResponse(BaseModel):
    report_id: str
    incident_id: str
    provider_used: str
    model_name: str | None
    safety_status: str
    validation_errors: list[str] = Field(default_factory=list)
    output: InvestigationOutput


class LlmReportSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    incident_id: str
    provider_used: str
    model_name: str | None
    safety_status: str
    created_at: datetime
    incident_summary_preview: str | None = None
    top_likely_cause_preview: str | None = None


class LlmReportListResponse(BaseModel):
    incident_id: str
    reports: list[LlmReportSummary]
    total: int
