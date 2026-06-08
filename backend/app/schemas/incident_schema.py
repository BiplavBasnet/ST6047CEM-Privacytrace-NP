from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IncidentStatus, Severity
from app.schemas.root_cause_schema import RootCauseScoreRead


class IncidentCreate(BaseModel):
    incident_id: str
    title: str
    affected_endpoint: str | None = None
    affected_service: str | None = None
    status: IncidentStatus = IncidentStatus.NEW
    severity: Severity = Severity.MEDIUM
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    summary: str | None = None


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: str
    title: str
    affected_endpoint: str | None
    affected_service: str | None
    status: IncidentStatus
    severity: Severity
    first_seen: datetime | None
    last_seen: datetime | None
    summary: str | None
    created_at: datetime
    updated_at: datetime


class IncidentDetailRead(IncidentRead):
    root_cause_scores: list[RootCauseScoreRead] = Field(default_factory=list)


class AnalyseIncidentRequest(BaseModel):
    incident_id: str | None = None
    force: bool = False


class AnalyseIncidentItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    status: str
    skipped: bool = False
    root_cause_count: int = 0
    top_likely_cause: str | None = None
    top_confidence_band: str | None = None
    error: str | None = None


class AnalyseIncidentResponse(BaseModel):
    results: list[AnalyseIncidentItem]
    total_scored: int = 0


class IncidentTraceResponse(BaseModel):
    incident_id: str
    title: str
    status: str
    affected_service: str | None
    affected_endpoint: str | None
    detection_count: int
    evidence_count: int
    analysis_stale: bool = False
    analysis_stale_reason: str | None = None
    analysis_version: int | None = None
    timeline: list[dict]
    likely_root_causes: list[dict]
    evidence_roles: list[dict] = Field(default_factory=list)
    score_breakdowns: list[dict] = Field(default_factory=list)
    correlation_reasons: list[str] = Field(default_factory=list)
    contradicting_evidence: list[dict] = Field(default_factory=list)
    missing_evidence: list[str]
    suggested_actions: list[dict] = Field(default_factory=list)
    trace_summary: dict = Field(default_factory=dict)
    reviewer_warning: str | None = None
    human_review_required: bool
    disclaimer: str
