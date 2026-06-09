from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


EvidenceRole = Literal[
    "symptom",
    "timeline",
    "correlation",
    "technical_cause",
    "contradiction",
    "remediation",
    "verification",
    "contextual",
]


class RootCauseEvidenceItem(BaseModel):
    evidence_id: str
    evidence_type: str
    evidence_role: EvidenceRole
    safe_summary: str
    support_reason: str
    source: str | None = None
    event_time: datetime | None = None


class CausalEvidenceStrength(BaseModel):
    """Pre-remediation technical case only — see `root_cause_evidence_strength_service`.

    Never influenced by human review approval, remediation completion, or
    fix-verification results (Phase M requirement 1).
    """

    incident_id: str | None
    likely_root_cause: str | None
    root_cause_category: str | None
    causal_confidence_level: str
    causal_confidence_score: float = Field(ge=0, le=1)
    causal_strength_level: Literal["weak", "medium", "strong", "very_strong"]
    causal_strength_score: float = Field(ge=0, le=1)
    causal_strength_reason: str
    causal_confidence_cap: str
    causal_confidence_cap_score: float = Field(ge=0, le=1)
    causal_confidence_cap_reason: str
    supporting_evidence: list[RootCauseEvidenceItem]
    contradicting_evidence: list[RootCauseEvidenceItem]
    symptom_evidence_count: int
    timeline_evidence_count: int
    technical_evidence_count: int
    matched_signals: list[dict]
    negative_signals: list[dict]
    contradiction_signals: list[dict]
    missing_evidence: list[str]
    recommended_next_evidence: list[str]
    excludes_post_remediation_evidence: bool = True
    limitations: list[str]


class PostRemediationValidation(BaseModel):
    """Remediation/retest/verification/review state only — separate from causal strength.

    (Phase M requirement 2.)
    """

    incident_id: str | None
    validation_status: Literal[
        "not_started",
        "remediation_recorded",
        "retested",
        "verified_passed",
        "verified_failed",
    ]
    validation_status_reason: str
    validation_score: float = Field(ge=0, le=1)
    remediation_evidence_count: int
    verification_evidence_count: int
    remediation_matches_cause: bool
    retest_matches_cause: bool
    verification_passed: bool
    verification_failed: bool
    review_approved: bool
    human_review_required: bool
    supporting_evidence: list[RootCauseEvidenceItem]
    missing_evidence: list[str]
    limitations: list[str]


class RootCauseEvidenceStrengthResponse(BaseModel):
    incident_id: str
    likely_root_cause: str | None
    root_cause_category: str | None
    confidence_level: str
    confidence_score: float = Field(ge=0, le=1)
    evidence_strength_level: Literal["weak", "medium", "strong", "very_strong"]
    evidence_strength_score: float = Field(ge=0, le=1)
    evidence_strength_reason: str
    confidence_cap: str
    confidence_cap_score: float = Field(ge=0, le=1)
    confidence_cap_reason: str
    supporting_evidence: list[RootCauseEvidenceItem]
    contradicting_evidence: list[RootCauseEvidenceItem]
    symptom_evidence_count: int
    timeline_evidence_count: int
    technical_evidence_count: int
    remediation_evidence_count: int
    verification_evidence_count: int
    matched_signals: list[dict]
    negative_signals: list[dict]
    contradiction_signals: list[dict]
    missing_evidence: list[str]
    recommended_next_evidence: list[str]
    human_review_required: bool
    limitations: list[str]
    causal_evidence_strength: CausalEvidenceStrength
    post_remediation_validation: PostRemediationValidation
