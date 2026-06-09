from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RootCauseScoreCreate(BaseModel):
    root_cause_id: str
    incident_id: str
    cause_name: str
    likely_root_cause: str
    confidence: float | None = None
    confidence_band: str | None = None
    rank: int | None = None
    supporting_evidence_ids: list[str] | None = None
    missing_evidence: list[str] | None = None
    score_breakdown: list[dict] | None = None
    matched_signals: list[dict] | None = None
    negative_signals: list[dict] | None = None
    correlation_reasons: list[str] | None = None
    contradicting_evidence: list[dict] | None = None
    context_evidence_ids: list[str] | None = None
    remediation_evidence_ids: list[str] | None = None
    retest_evidence_ids: list[str] | None = None
    evidence_roles: list[dict] | None = None
    suggested_actions: list[dict] | None = None
    recommended_fix: str | None = None
    human_review_required: bool = True
    explanation: str | None = None
    analysis_id: str | None = None
    analysis_version: int = 1
    rules_version: str | None = None
    evidence_snapshot_hash: str | None = None
    analysed_at: datetime | None = None
    stale: bool = False
    stale_reason: str | None = None
    superseded_by_analysis_id: str | None = None


class RootCauseScoreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    root_cause_id: str
    incident_id: str
    cause_name: str
    likely_root_cause: str
    confidence: float | None
    confidence_band: str | None
    rank: int | None
    supporting_evidence_ids: list | None
    missing_evidence: list | None
    score_breakdown: list[dict] = Field(default_factory=list)
    matched_signals: list[dict] = Field(default_factory=list)
    negative_signals: list[dict] = Field(default_factory=list)
    correlation_reasons: list[str] = Field(default_factory=list)
    contradicting_evidence: list[dict] = Field(default_factory=list)
    context_evidence_ids: list[str] = Field(default_factory=list)
    remediation_evidence_ids: list[str] = Field(default_factory=list)
    retest_evidence_ids: list[str] = Field(default_factory=list)
    evidence_roles: list[dict] = Field(default_factory=list)
    suggested_actions: list[dict] = Field(default_factory=list)
    recommended_fix: str | None
    human_review_required: bool
    explanation: str | None
    created_at: datetime
    analysis_id: str | None = None
    analysis_version: int = 1
    rules_version: str | None = None
    evidence_snapshot_hash: str | None = None
    analysed_at: datetime | None = None
    stale: bool = False
    stale_reason: str | None = None
    superseded_by_analysis_id: str | None = None


class RootCauseAnalysisStatus(BaseModel):
    """Lightweight staleness/versioning summary for one incident's analysis."""

    incident_id: str
    analysed: bool
    analysis_id: str | None = None
    analysis_version: int | None = None
    rules_version: str | None = None
    evidence_snapshot_hash: str | None = None
    analysed_at: datetime | None = None
    stale: bool = False
    stale_reason: str | None = None
    root_cause_count: int = 0
    top_likely_cause: str | None = None
    superseded_by_analysis_id: str | None = None
