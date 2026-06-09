"""Pydantic schemas for Phase 11.85 ScannerBridge-NP."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SUPPORTED_SOURCE_FORMATS = (
    "generic_secret_scanner_json",
    "external_secret_scanner_json",
    "gitleaks_json",
    "semgrep_sarif",
    "semgrep_json",
)

# NOTE: ingested scanner `explanation` text is INPUT evidence (it may quote
# the scanner tool's own wording, e.g. a SAST rule description) and is
# intentionally NOT rejected for narrative/certainty wording here. It is
# still scanned for raw secrets by `scanner_validation_service` /
# `input_evidence_safety_service` before persistence. See
# docs/INPUT_OUTPUT_SAFETY_SEPARATION.md.


class ScannerImportBody(BaseModel):
    """JSON import body (alternative to multipart)."""

    source_format: str = Field(..., min_length=1, max_length=64)
    payload: dict[str, Any] | list[Any] | str
    linked_incident_id: str | None = Field(None, max_length=64)
    source_system: str | None = Field(None, max_length=255)
    service_hint: str | None = Field(None, max_length=255)
    endpoint_hint: str | None = Field(None, max_length=512)
    release_version_hint: str | None = Field(None, max_length=128)


class ScannerPreviewFinding(BaseModel):
    detector_name: str | None = None
    finding_type: str | None = None
    masked_value: str | None = None
    source_file: str | None = None
    line_number: int | None = None
    severity: str | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    verification_status: str | None = None
    safety_status: str = "safe"
    repository: str | None = None
    commit_id: str | None = None


class ScannerPreviewResponse(BaseModel):
    detected_format: str
    safe_preview_findings: list[ScannerPreviewFinding]
    unsafe_item_count: int
    warnings: list[str] = Field(default_factory=list)
    import_allowed: bool


class ScannerImportResponse(BaseModel):
    status: str
    imported_count: int
    rejected_count: int
    scanner_evidence_ids: list[str] = Field(default_factory=list)
    linked_incident_id: str | None = None
    import_evidence_id: str | None = None
    safety_warnings: list[str] = Field(default_factory=list)
    message: str


class ScannerEvidenceSafeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scanner_evidence_id: str
    source_format: str
    scanner_category: str | None = None
    finding_type: str | None = None
    detector_name: str | None = None
    verification_status: str | None = None
    severity: str | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    causal_relevance_score: float | None = Field(None, ge=0.0, le=1.0)
    repository: str | None = None
    source_file: str | None = None
    line_number: int | None = None
    commit_id: str | None = None
    branch: str | None = None
    masked_value: str | None = None
    evidence_reference: str
    linked_evidence_id: str | None = None
    linked_incident_id: str | None = None
    service_hint: str | None = None
    endpoint_hint: str | None = None
    release_version_hint: str | None = None
    detected_at: datetime | None = None
    imported_at: datetime | None = None
    safety_status: str
    raw_payload_hash: str | None = None
    tags: list[str] = Field(default_factory=list)
    explanation: str | None = None
    import_evidence_id: str | None = None


class ScannerLinkRequest(BaseModel):
    incident_id: str = Field(..., min_length=1, max_length=64)


class ScannerCorrelationItem(BaseModel):
    scanner_evidence_id: str
    causal_relevance_score: float
    detector_name: str | None = None
    masked_value: str | None = None
    source_file: str | None = None
    explanation: str | None = None


class ScannerCorrelationResponse(BaseModel):
    incident_id: str
    scanner_evidence_count: int
    strong_supporting_evidence: list[ScannerCorrelationItem] = Field(default_factory=list)
    moderate_supporting_evidence: list[ScannerCorrelationItem] = Field(default_factory=list)
    weak_supporting_evidence: list[ScannerCorrelationItem] = Field(default_factory=list)
    top_scanner_evidence: list[ScannerCorrelationItem] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    human_review_required: bool = True
    summary: str
