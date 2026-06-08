from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CounterfactualAnalysis(Base):
    __tablename__ = "counterfactual_analyses"
    __table_args__ = (
        UniqueConstraint("root_cause_id", "causal_ruleset_version", "input_fingerprint", name="uq_counterfactual_idempotency"),
        Index("ix_counterfactual_incident_created", "incident_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False)
    root_cause_id: Mapped[str] = mapped_column(ForeignKey("root_cause_scores.root_cause_id", ondelete="RESTRICT"), index=True, nullable=False)
    causal_ruleset_version: Mapped[str] = mapped_column(String(128), nullable=False)
    method_version: Mapped[str] = mapped_column(String(64), nullable=False, default="counterfactual-removal-v2")
    input_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    baseline_score: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    stability_level: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    fragile_conclusion: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    minimal_evidence_set: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    missing_evidence_recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    test_results: Mapped[list["CounterfactualTestResult"]] = relationship(back_populates="analysis", order_by="CounterfactualTestResult.id")


class CounterfactualTestResult(Base):
    __tablename__ = "counterfactual_test_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    test_result_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("counterfactual_analyses.analysis_id", ondelete="RESTRICT"), index=True, nullable=False)
    test_type: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_role: Mapped[str] = mapped_column(String(32), nullable=False)
    score_before: Mapped[float] = mapped_column(Float, nullable=False)
    score_after: Mapped[float] = mapped_column(Float, nullable=False)
    score_change: Mapped[float] = mapped_column(Float, nullable=False)
    rank_before: Mapped[int] = mapped_column(Integer, nullable=False)
    rank_after: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rank_changed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    importance_level: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    analysis: Mapped[CounterfactualAnalysis] = relationship(back_populates="test_results")
