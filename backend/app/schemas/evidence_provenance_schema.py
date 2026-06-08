from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


RelationshipType = Literal[
    "was_derived_from", "was_generated_by", "was_collected_by", "was_normalised_by",
    "was_used_by", "was_associated_with", "supports", "contradicts", "correlates_with",
    "part_of_trace", "produced_decision", "produced_report", "produced_retest",
]


class EvidenceProvenanceUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_system: str | None = Field(default=None, max_length=255)
    source_event_id: str | None = Field(default=None, max_length=255)
    source_format: str | None = Field(default=None, max_length=64)
    source_timestamp: datetime | None = None
    collection_timestamp: datetime | None = None
    collector_name: str | None = Field(default=None, max_length=128)
    collector_version: str | None = Field(default=None, max_length=64)
    parser_name: str | None = Field(default=None, max_length=128)
    parser_version: str | None = Field(default=None, max_length=64)
    normalisation_version: str | None = Field(default=None, max_length=64)
    service_name: str | None = Field(default=None, max_length=128)
    service_version: str | None = Field(default=None, max_length=64)
    deployment_environment: str | None = Field(default=None, max_length=64)
    host_reference: str | None = Field(default=None, max_length=255)
    container_reference: str | None = Field(default=None, max_length=255)
    trace_id: str | None = Field(default=None, max_length=128)
    span_id: str | None = Field(default=None, max_length=128)
    parent_span_id: str | None = Field(default=None, max_length=128)
    commit_sha: str | None = Field(default=None, max_length=128)
    configuration_hash: str | None = Field(default=None, max_length=128)
    content_sha256: str | None = Field(default=None, max_length=128)
    parent_evidence_id: str | None = Field(default=None, max_length=64)


class EvidenceProvenanceRead(EvidenceProvenanceUpsertRequest):
    model_config = ConfigDict(from_attributes=True)
    provenance_id: str
    evidence_id: str
    ingestion_timestamp: datetime
    provenance_status: str
    created_at: datetime
    updated_at: datetime


class ProvenanceRelationshipCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_entity_type: str = Field(min_length=1, max_length=64)
    source_entity_id: str = Field(min_length=1, max_length=128)
    target_entity_type: str = Field(min_length=1, max_length=64)
    target_entity_id: str = Field(min_length=1, max_length=128)
    relationship_type: RelationshipType
    reason: str = Field(min_length=5, max_length=2000)
    confidence_type: Literal["direct", "inferred", "unverified"] = "unverified"


class ProvenanceRelationshipRead(ProvenanceRelationshipCreate):
    model_config = ConfigDict(from_attributes=True)
    relationship_id: str
    validation_status: str
    created_by: int | None
    created_at: datetime


class ProvenanceValidationResponse(BaseModel):
    evidence_id: str
    status: Literal["complete", "partial", "invalid", "unverified"]
    issues: list[dict] = Field(default_factory=list)
    checked_at: datetime


class IncidentProvenanceResponse(BaseModel):
    incident_id: str
    evidence: list[EvidenceProvenanceRead] = Field(default_factory=list)
    relationships: list[ProvenanceRelationshipRead] = Field(default_factory=list)
    status: str


class ProvenancePathResponse(BaseModel):
    start_entity_type: str
    start_entity_id: str
    paths: list[list[dict]] = Field(default_factory=list)
    status: str
