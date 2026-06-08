"""First-class root-cause analysis identity (versioned, stale-aware)."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class RootCauseAnalysis(Base):
    __tablename__ = "root_cause_analyses"
    __table_args__ = (
        UniqueConstraint("incident_id", "analysis_version", name="uq_root_cause_incident_version"),
        Index(
            "uq_root_cause_current_incident",
            "incident_id",
            unique=True,
            postgresql_where=text("current IS TRUE"),
            sqlite_where=text("current = 1"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    analysis_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    rules_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    taxonomy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exposure_policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    analysed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stale: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stale_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    superseded_by_analysis_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident")
