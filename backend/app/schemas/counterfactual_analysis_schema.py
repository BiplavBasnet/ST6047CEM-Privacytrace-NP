from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CounterfactualRunRequest(BaseModel):
    root_cause_id: str | None = Field(default=None, max_length=64)
    max_evidence_items: int = Field(default=25, ge=1, le=100)


class CounterfactualTestResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    test_result_id: str
    test_type: str
    evidence_id: str | None
    evidence_role: str
    score_before: float
    score_after: float
    score_change: float
    rank_before: int
    rank_after: int | None
    rank_changed: bool
    importance_level: str
    explanation: str
    created_at: datetime


class CounterfactualAnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    analysis_id: str
    incident_id: str
    root_cause_id: str
    causal_ruleset_version: str
    method_version: str
    baseline_score: float
    baseline_rank: int
    stability_level: str
    fragile_conclusion: bool
    minimal_evidence_set: list[str]
    missing_evidence_recommendations: list[str]
    limitations: list[str]
    created_at: datetime
    created_by: int | None
    test_results: list[CounterfactualTestResultRead] = Field(default_factory=list)


class CounterfactualAnalysisListResponse(BaseModel):
    analyses: list[CounterfactualAnalysisRead]
    total: int


class CounterfactualRunResponse(BaseModel):
    analysis: CounterfactualAnalysisRead
    created: bool
    disclaimer: str = "This is rule-based counterfactual analysis and not proof of causation."
