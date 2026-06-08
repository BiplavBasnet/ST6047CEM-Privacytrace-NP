from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EvidenceProvenance(Base):
    __tablename__ = "evidence_provenance"
    __table_args__ = (UniqueConstraint("evidence_id", name="uq_evidence_provenance_evidence"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    provenance_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_files.evidence_id", ondelete="RESTRICT"), index=True, nullable=False)
    source_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_format: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collection_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ingestion_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    collector_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    collector_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    normalisation_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deployment_environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    container_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    span_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parent_span_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(128), nullable=True)
    configuration_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parent_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence_files.evidence_id", ondelete="RESTRICT"), nullable=True, index=True)
    provenance_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class ProvenanceRelationship(Base):
    __tablename__ = "provenance_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_entity_type", "source_entity_id", "target_entity_type", "target_entity_id", "relationship_type",
            name="uq_provenance_relationship_edge",
        ),
        Index("ix_provenance_relationship_source", "source_entity_type", "source_entity_id"),
        Index("ix_provenance_relationship_target", "target_entity_type", "target_entity_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    relationship_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    source_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
