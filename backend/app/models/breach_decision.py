from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class BreachDecisionRecord(Base):
    __tablename__ = "breach_decision_records"
    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_breach_decision_decision_id"),
        UniqueConstraint("incident_id", "decision_version", name="uq_breach_decision_incident_version"),
        Index(
            "uq_breach_decision_latest_incident",
            "incident_id",
            unique=True,
            postgresql_where=text("superseded_by_record_id IS NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("privacy_impact_assessments.assessment_id", ondelete="RESTRICT"), index=True, nullable=False)
    decision_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", index=True)
    breach_determination: Mapped[str] = mapped_column(String(32), nullable=False, default="insufficient_evidence")
    assessment_method_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    root_cause_ruleset_version: Mapped[str] = mapped_column(String(128), nullable=False)
    taxonomy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    combination_ruleset_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    affected_data_categories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    affected_subject_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    affected_subject_count_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    severity_inputs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    privacy_harm_inputs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    root_cause_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    severity_result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    privacy_harm_result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    alert_recommendation: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    containment_recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    customer_notification_recommendation: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    missing_information: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    uncertainties: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    exposure_profile_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    internal_only_restrictions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    human_override_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    human_override_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    supersedes_record_id: Mapped[str | None] = mapped_column(ForeignKey("breach_decision_records.decision_id", ondelete="RESTRICT"), nullable=True, index=True)
    superseded_by_record_id: Mapped[str | None] = mapped_column(ForeignKey("breach_decision_records.decision_id", ondelete="RESTRICT"), nullable=True, index=True)
    integrity_record_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    factors: Mapped[list["BreachDecisionFactor"]] = relationship(back_populates="decision", order_by="BreachDecisionFactor.id")


class BreachDecisionFactor(Base):
    __tablename__ = "breach_decision_factors"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    decision_record_id: Mapped[str] = mapped_column(ForeignKey("breach_decision_records.decision_id", ondelete="RESTRICT"), index=True, nullable=False)
    factor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    factor_code: Mapped[str] = mapped_column(String(128), nullable=False)
    factor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    score_contribution: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    method_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    decision: Mapped[BreachDecisionRecord] = relationship(back_populates="factors")
