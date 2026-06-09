from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GenerateReportRequest(BaseModel):
    report_type: Literal["json", "html"] = "json"


class IncidentReportContent(BaseModel):
    model_config = ConfigDict(extra="allow")

    incident_id: str
    affected_service: str | None = None
    affected_endpoint: str | None = None
    severity: str | None = None
    status: str
    masked_detections: list[dict[str, Any]] = Field(default_factory=list)
    linked_evidence_ids: list[str] = Field(default_factory=list)
    likely_root_causes: list[dict[str, Any]] = Field(default_factory=list)
    top_likely_root_cause: str | None = None
    confidence_band: str | None = None
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_fix: str | None = None
    safety_statement: str
    human_review_required: bool = True


class GenerateReportResponse(BaseModel):
    report_id: int
    incident_id: str
    report_type: str
    created_at: datetime
    content: dict[str, Any]
    html_document: str | None = None
    message: str = "Incident report generated and stored safely."


class IncidentReportSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: int
    incident_id: str
    report_type: str
    created_at: datetime
    content: dict[str, Any]
    html_document: str | None = None
    report_version: int = 1
    history_status: str = "historical"
    current_chain_match_at_export: bool = False


class IncidentReportListResponse(BaseModel):
    incident_id: str
    reports: list[IncidentReportSummary]
    total: int
