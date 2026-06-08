"""ScannerBridge-NP normalised external scanner evidence records."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile
    from app.models.incident import Incident


class ScannerEvidenceRecord(Base):
    __tablename__ = "scanner_evidence_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scanner_evidence_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    import_evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_format: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    finding_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detector_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    verification_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="scanner_evidence_severity", native_enum=False),
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    causal_relevance_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    repository: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_number: Mapped[int | None] = mapped_column(nullable=True)
    commit_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(256), nullable=True)
    masked_value: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    linked_evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    service_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint_hint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    release_version_hint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False, default="safe")
    raw_payload_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    import_evidence_file: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        foreign_keys=[import_evidence_id],
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident",
        foreign_keys=[linked_incident_id],
    )
