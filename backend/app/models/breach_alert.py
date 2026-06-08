from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class BreachAlert(Base):
    __tablename__ = "breach_alerts"
    __table_args__ = (
        CheckConstraint("occurrence_count >= 1", name="ck_breach_alert_occurrence_positive"),
        CheckConstraint("duplicate_count >= 0", name="ck_breach_alert_duplicate_nonnegative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("privacy_impact_assessments.assessment_id", ondelete="RESTRICT"), index=True, nullable=False)
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="suspected", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    reason_codes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    affected_subject_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    credential_exposure_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_acknowledgement: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deduplication_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    deduplication_signature: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    deduplication_window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    duplicate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assessment_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_system_grouping: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    public_exposure_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    external_access_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assigned_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    assigned_team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledgement_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    containment_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    escalation_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    suppression_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    suppression_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppression_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppression_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    suppressed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    escalation_level: Mapped[str] = mapped_column(String(48), nullable=False, default="none", index=True)
    escalation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reopened_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reopen_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolution_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

class BreachAlertEvidenceLink(Base):
    __tablename__ = "breach_alert_evidence_links"
    __table_args__ = (
        UniqueConstraint("alert_id", "evidence_id", name="uq_breach_alert_evidence"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("breach_alerts.alert_id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
