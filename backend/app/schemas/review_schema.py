from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ReviewDecisionValue = Literal[
    "approved",
    "request_more_evidence",
    "rejected_false_positive",
    "escalated",
    # Backward-compatible aliases accepted by earlier API clients.
    "rejected",
    "inconclusive",
]


class ReviewDecisionCreate(BaseModel):
    incident_id: str
    reviewer_id: int | None = None
    decision: str
    comment: str | None = None


class SubmitReviewRequest(BaseModel):
    decision: ReviewDecisionValue
    reason: str | None = Field(
        default=None,
        max_length=2000,
        description="Required reason for the final human decision.",
    )
    comment: str | None = Field(
        default=None,
        max_length=2000,
        description="Investigation note for the audit trail (no raw sensitive values).",
    )
    evidence_checklist: list[str] = Field(default_factory=list, max_length=20)
    evidence_relied_on: list[str] = Field(default_factory=list, max_length=100)
    evidence_limitations: str | None = Field(default=None, max_length=2000)
    missing_evidence_acknowledged: bool = False

    @model_validator(mode="after")
    def require_reason_or_legacy_comment(self):
        if not (self.reason or self.comment or "").strip():
            raise ValueError("A decision reason is required.")
        return self


class ReviewDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: str
    reviewer_id: int | None
    decision: str
    comment: str | None
    reason: str | None
    evidence_checklist: list[str]
    evidence_relied_on: list[str]
    evidence_limitations: str | None
    missing_evidence_acknowledged: bool
    timestamp: datetime


class SubmitReviewResponse(BaseModel):
    review: ReviewDecisionRead
    incident_status: str
    audit_log_id: int
    message: str = "Review recorded; incident status updated."


class ReviewListResponse(BaseModel):
    incident_id: str
    reviews: list[ReviewDecisionRead]
    total: int


class ReviewDraftUpsert(BaseModel):
    selected_decision: ReviewDecisionValue | None = None
    reason: str | None = Field(default=None, max_length=2000)
    evidence_checklist: list[str] = Field(default_factory=list, max_length=20)
    evidence_relied_on: list[str] = Field(default_factory=list, max_length=100)
    evidence_limitations: str | None = Field(default=None, max_length=2000)
    missing_evidence_notes: str | None = Field(default=None, max_length=2000)
    missing_evidence_acknowledged: bool = False


class ReviewDraftRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    selected_decision: str | None
    reason: str | None
    evidence_checklist: list[str]
    evidence_relied_on: list[str]
    evidence_limitations: str | None
    missing_evidence_notes: str | None
    missing_evidence_acknowledged: bool
    last_updated_by: int | None
    last_updated_at: datetime
