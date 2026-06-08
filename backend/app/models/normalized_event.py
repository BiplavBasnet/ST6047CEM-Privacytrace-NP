from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile
    from app.models.incident import Incident


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_type: Mapped[str] = mapped_column(String(128), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    release_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    masked_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="event_severity", native_enum=False),
        nullable=True,
    )
    linked_incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # --- Phase K: durable cross-source correlation (see docs/LIVE_CORRELATION_MODEL.md) ---
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    trace_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    request_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    correlation_fingerprint_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    correlation_fingerprint_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    transaction_reference_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_reference_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    deployment_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    configuration_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_time_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    time_quality: Mapped[str | None] = mapped_column(String(64), nullable=True)
    time_inferred: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    timezone_name: Mapped[str | None] = mapped_column(String(64), nullable=True)

    evidence_file: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        back_populates="normalized_events",
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident",
        back_populates="normalized_events",
        foreign_keys=[linked_incident_id],
    )
