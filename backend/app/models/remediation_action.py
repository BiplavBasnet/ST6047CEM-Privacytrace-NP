from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index(
            "uq_remediation_actions_diagnosis",
            "diagnosis_id",
            unique=True,
            postgresql_where=text("diagnosis_id IS NOT NULL"),
            sqlite_where=text("diagnosis_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    remediation_action_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    diagnosis_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("remediation_diagnoses.diagnosis_id", ondelete="RESTRICT"),
        nullable=True, index=True
    )
    root_cause_analysis_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"),
        nullable=True, index=True
    )
    review_decision_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("review_decisions.id", ondelete="RESTRICT"), nullable=True
    )
    approved_payload_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    action_description: Mapped[str] = mapped_column(Text, nullable=False)
    approved_problem_statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_change: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    affected_component: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    affected_function: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_configuration: Mapped[str | None] = mapped_column(String(255), nullable=True)
    implementation_steps: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    required_tests: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    retest_requirements: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    risks: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    implementation_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assigned_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_started")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    target_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    retest_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    completion_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    requires_revalidation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="remediation_actions"
    )
