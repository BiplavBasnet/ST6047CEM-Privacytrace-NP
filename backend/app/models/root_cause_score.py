from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class RootCauseScore(Base):
    __tablename__ = "root_cause_scores"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    root_cause_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cause_name: Mapped[str] = mapped_column(String(255), nullable=False)
    likely_root_cause: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence_band: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rank: Mapped[int | None] = mapped_column(Integer, nullable=True)
    supporting_evidence_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    missing_evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    score_breakdown: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    matched_signals: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    negative_signals: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    correlation_reasons: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    contradicting_evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    context_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    remediation_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    retest_evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    suggested_actions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recommended_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    human_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # --- Phase N: root-cause analysis versioning + staleness (see
    # docs/ROOT_CAUSE_ANALYSIS_VERSIONING.md). All rows created by one
    # `analyse_incident` call share the same `analysis_id`/`analysis_version`;
    # re-analysing an incident never mutates or deletes a prior batch, it
    # only marks it superseded/stale. ---
    analysis_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    analysis_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    rules_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence_snapshot_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analysed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stale: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    stale_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    superseded_by_analysis_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="root_cause_scores",
    )
