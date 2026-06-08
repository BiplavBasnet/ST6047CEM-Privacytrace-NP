from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import VerificationStatus

if TYPE_CHECKING:
    from app.models.incident import Incident


class FixVerification(Base):
    __tablename__ = "fix_verifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    verification_status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus, name="verification_status", native_enum=False),
        nullable=False,
    )
    root_cause_analysis_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"), nullable=True)
    review_decision_id: Mapped[int | None] = mapped_column(ForeignKey("review_decisions.id", ondelete="RESTRICT"), nullable=True)
    remediation_diagnosis_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_diagnoses.diagnosis_id", ondelete="RESTRICT"), nullable=True)
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_actions.remediation_action_id", ondelete="RESTRICT"), nullable=True)
    implementation_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_implementation_records.implementation_id", ondelete="RESTRICT"), nullable=True)
    test_execution_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_test_executions.execution_id", ondelete="RESTRICT"), nullable=True)
    controlled_retest_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("controlled_retests.controlled_retest_id", ondelete="RESTRICT"), nullable=True, unique=True)
    checks_run: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    passed_checks: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    failed_checks: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    evidence_used: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="fix_verifications",
    )
