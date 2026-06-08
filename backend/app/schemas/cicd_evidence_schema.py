from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


CicdEvidenceType = Literal[
    "pipeline_run",
    "deployment_event",
    "commit_metadata",
    "changed_files",
    "security_scan_result",
    "test_result",
    "rollback_event",
    "configuration_change",
    "release_metadata",
]


class CicdEvidenceImport(BaseModel):
    source_name: str = Field(min_length=1, max_length=255)
    evidence_type: CicdEvidenceType
    environment: str | None = Field(default=None, max_length=64)
    service_name: str | None = Field(default=None, max_length=255)
    pipeline_id: str | None = Field(default=None, max_length=128)
    deployment_version: str | None = Field(default=None, max_length=128)
    commit_reference: str | None = Field(default=None, max_length=128)
    changed_file_paths_safe: list[str] = Field(default_factory=list, max_length=100)
    change_categories: list[str] = Field(default_factory=list, max_length=30)
    scan_summary_safe: str | None = Field(default=None, max_length=2000)
    test_summary_safe: str | None = Field(default=None, max_length=2000)
    event_time: datetime | None = None
    linked_incident_id: str | None = Field(default=None, max_length=64)

    @field_validator("changed_file_paths_safe")
    @classmethod
    def validate_safe_paths(cls, paths: list[str]) -> list[str]:
        for path in paths:
            if not path.strip() or len(path) > 1024 or "\n" in path or "\r" in path:
                raise ValueError("Changed file paths must be short single-line path labels.")
        return paths


class CicdEvidenceBatchImport(BaseModel):
    items: list[CicdEvidenceImport] = Field(min_length=1, max_length=100)


class CicdEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cicd_evidence_id: str
    source_name: str
    evidence_type: str
    environment: str | None
    service_name: str | None
    pipeline_id: str | None
    deployment_version: str | None
    commit_reference: str | None
    changed_file_paths_safe: list[str]
    change_categories: list[str]
    scan_summary_safe: str | None
    test_summary_safe: str | None
    event_time: datetime | None
    received_at: datetime
    raw_event_hash: str
    linked_incident_id: str | None
    safety_status: str


class CicdEvidenceListResponse(BaseModel):
    items: list[CicdEvidenceRead]
    total: int


class CicdEvidenceLinkRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=64)


class CicdCorrelationItem(BaseModel):
    cicd_evidence_id: str
    score: float = Field(ge=0, le=1)
    reasons: list[str]
    linked: bool


class CicdCorrelationResponse(BaseModel):
    incident_id: str
    candidates: list[CicdCorrelationItem]
    total: int
    note: str = "Correlation is supporting evidence and requires human review."
