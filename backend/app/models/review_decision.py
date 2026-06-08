from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.user import User


class ReviewDecision(Base):
    __tablename__ = "review_decisions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    reviewer_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    decision: Mapped[str] = mapped_column(String(128), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_checklist: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_relied_on: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    missing_evidence_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # Provenance: review is valid for progression only when bound to the
    # current RootCauseAnalysis and matching evidence_snapshot_hash.
    root_cause_analysis_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"),
        nullable=True, index=True
    )
    root_cause_analysis_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_snapshot_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    limitations_acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    progression_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    progression_invalid_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="review_decisions",
    )
    reviewer: Mapped["User | None"] = relationship(
        "User",
        back_populates="review_decisions",
    )
