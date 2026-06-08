from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    report_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    root_cause_analysis_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"), nullable=True
    )
    root_cause_analysis_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_snapshot_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    review_decision_id: Mapped[int | None] = mapped_column(ForeignKey("review_decisions.id", ondelete="RESTRICT"), nullable=True)
    remediation_diagnosis_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_diagnoses.diagnosis_id", ondelete="RESTRICT"), nullable=True)
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_actions.remediation_action_id", ondelete="RESTRICT"), nullable=True)
    implementation_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_implementation_records.implementation_id", ondelete="RESTRICT"), nullable=True)
    patch_proposal_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("patch_proposals.patch_proposal_id", ondelete="RESTRICT"), nullable=True)
    test_execution_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_test_executions.execution_id", ondelete="RESTRICT"), nullable=True)
    controlled_retest_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("controlled_retests.controlled_retest_id", ondelete="RESTRICT"), nullable=True)
    fix_verification_id: Mapped[int | None] = mapped_column(ForeignKey("fix_verifications.id", ondelete="RESTRICT"), nullable=True)
    verification_outcome_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("verification_outcomes.verification_outcome_id", ondelete="RESTRICT"), nullable=True)
    recommendation_policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    taxonomy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exposure_policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    workflow_chain_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="blocked", server_default="blocked"
    )
    content_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    content_encrypted: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    content_crypto_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="reports",
    )
