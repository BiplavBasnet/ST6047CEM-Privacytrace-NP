from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile
    from app.models.incident import Incident


class PrivacyAlert(Base):
    __tablename__ = "privacy_alerts"
    __table_args__ = (
        Index(
            "uq_privacy_alert_integrity_failure",
            "integrity_failure_fingerprint",
            unique=True,
            postgresql_where=text("integrity_failure_fingerprint IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    alert_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(String(128), nullable=False)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_format: Mapped[str] = mapped_column(String(64), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="privacy_alert_severity", native_enum=False),
        nullable=False,
        default=Severity.MEDIUM,
    )
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="new", index=True)
    sensitive_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    masked_values: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    detection_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    linked_incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    raw_event_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    integrity_failure_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False, default="safe")
    alert_summary: Mapped[str] = mapped_column(Text, nullable=False)
    human_review_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    ingestion_source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="live_monitor",
        server_default="live_monitor",
    )
    missing_metadata: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    correlation_recommendations: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    evidence_strength: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="limited",
        server_default="limited",
    )
    # --- Phase I: real alert grouping (see docs/LIVE_ALERT_GROUPING.md) ---
    alert_group_key: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    repeat_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    affected_trace_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    trace_count_quality: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unavailable", server_default="unavailable"
    )
    grouping_rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_source_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_source_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_time_quality: Mapped[str] = mapped_column(
        String(32), nullable=False, default="inferred", server_default="inferred"
    )
    source_time_inferred: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    source_timezone_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exposure_location: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Safe (no raw value) per-sensitive-type finding snapshot captured from the
    # exposure engine at alert-creation/recurrence time: sensitive_type,
    # confidence_score, confidence_level, value_fingerprint, masked_preview,
    # severity, exposure_location. Lets alert->incident Detection creation use
    # real per-value confidence/fingerprints instead of a hardcoded 0.92 /
    # None (see `live_monitor_service._ensure_alert_evidence`).
    alert_findings: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Last-seen correlation keys from live ingest (trace_id, request_id, …).
    # Persisted so NormalizedEvent creation at incident-link time can copy them.
    correlation_keys: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident | None"] = relationship("Incident", foreign_keys=[linked_incident_id])
    evidence_file: Mapped["EvidenceFile | None"] = relationship("EvidenceFile", foreign_keys=[evidence_id])
