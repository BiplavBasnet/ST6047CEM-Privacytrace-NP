from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class ReviewDraft(Base):
    __tablename__ = "review_drafts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    selected_decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_checklist: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_relied_on: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    missing_evidence_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    missing_evidence_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    last_updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="review_draft")
