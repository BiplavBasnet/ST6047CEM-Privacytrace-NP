from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PreventiveControl(Base):
    __tablename__ = "preventive_controls"
    __table_args__ = (
        UniqueConstraint("control_id", name="uq_preventive_control_control_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    control_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False
    )
    root_cause_id: Mapped[str] = mapped_column(
        ForeignKey("root_cause_scores.root_cause_id", ondelete="RESTRICT"), index=True, nullable=False
    )
    # Approved decision history is protected by the additive governance migration.
    decision_record_id: Mapped[str | None] = mapped_column(
        ForeignKey("breach_decision_records.decision_id", ondelete="RESTRICT"), nullable=True, index=True
    )
    remediation_action_id: Mapped[str | None] = mapped_column(
        ForeignKey("remediation_actions.remediation_action_id", ondelete="RESTRICT"),
        nullable=True,
    )
    control_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)
    control_description: Mapped[str] = mapped_column(Text, nullable=False)
    generated_content: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str | None] = mapped_column(String(48), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    source: Mapped[str] = mapped_column(String(48), nullable=False)
    generation_method: Mapped[str] = mapped_column(String(96), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    implementation_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    implemented_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    implemented_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_started", index=True
    )
    verification_method: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verification_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    supersedes_control_id: Mapped[str | None] = mapped_column(
        ForeignKey("preventive_controls.control_id", ondelete="RESTRICT"), nullable=True
    )
    retired_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retirement_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class PreventiveControlEvidenceLink(Base):
    __tablename__ = "preventive_control_evidence_links"
    __table_args__ = (
        UniqueConstraint("control_id", "evidence_id", "evidence_role", name="uq_control_evidence_role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    control_id: Mapped[str] = mapped_column(
        ForeignKey("preventive_controls.control_id", ondelete="RESTRICT"), index=True, nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="RESTRICT"), index=True, nullable=False
    )
    evidence_role: Mapped[str] = mapped_column(String(32), nullable=False, default="retest")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
