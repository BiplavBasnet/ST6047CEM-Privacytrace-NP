from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.user import User


class RemediationDiagnosis(Base):
    """Persisted problem-specific remediation diagnosis awaiting human review."""

    __tablename__ = "remediation_diagnoses"
    __table_args__ = (
        Index(
            "uq_remediation_diagnosis_current_branch",
            "incident_id", "root_cause_analysis_id", "review_decision_id",
            unique=True,
            postgresql_where=text("workflow_status = 'current'"),
            sqlite_where=text("workflow_status = 'current'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    diagnosis_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    root_cause_analysis_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"),
        nullable=True, index=True
    )
    root_cause_analysis_version: Mapped[int | None] = mapped_column(nullable=True)
    evidence_snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    review_decision_id: Mapped[int | None] = mapped_column(
        ForeignKey("review_decisions.id", ondelete="RESTRICT"), nullable=True
    )
    generation_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    playbook_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    playbook_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ai_failure_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fallback_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    derived_from_stale_analysis: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    model_provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    prompt_template_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recommendation_policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    problem_statement: Mapped[str] = mapped_column(Text, nullable=False)
    technical_mechanism: Mapped[str] = mapped_column(Text, nullable=False)
    affected_service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    affected_component: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    affected_function: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_configuration: Mapped[str | None] = mapped_column(String(255), nullable=True)
    exact_source_location_known: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    supporting_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    contradicting_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    missing_evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    diagnosis_confidence: Mapped[str] = mapped_column(String(64), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    primary_remediation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    alternative_remediations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    exact_change_available: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    proposed_change: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    original_ai_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    approved_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    edited_fields: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reviewer_decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident")
    created_by: Mapped["User | None"] = relationship("User", foreign_keys=[created_by_user_id])
    reviewed_by: Mapped["User | None"] = relationship("User", foreign_keys=[reviewed_by_user_id])
