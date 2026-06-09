from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvaluationMetricRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    metric_name: str
    metric_value: float | None
    scenario_name: str | None
    thesis_claim: str | None
    baseline_name: str | None
    calculation_method: str | None
    evidence_source: str | None
    created_at: datetime


class RunEvaluationRequest(BaseModel):
    scenario_name: str = Field(default="scenario_1", min_length=1, max_length=128)


class RunEvaluationResponse(BaseModel):
    scenario_name: str
    incident_id: str
    metrics_computed: int
    metrics: list[EvaluationMetricRead]
    message: str = "Thesis-aligned evaluation metrics recorded."


class EvaluationMetricsListResponse(BaseModel):
    scenario_name: str | None = None
    metrics: list[EvaluationMetricRead]
    total: int
    context_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Non-core context counts (e.g. evidence files) for reports only.",
    )
