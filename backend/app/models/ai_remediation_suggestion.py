from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.user import User


class AIRemediationSuggestion(Base):
    __tablename__ = "ai_remediation_suggestions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    suggestion_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    ai_provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ai_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    input_safety_status: Mapped[str] = mapped_column(String(64), nullable=False)
    output_safety_status: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    masked_input_summary_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    suggestion_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    likely_issue_area: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_actions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    code_or_config_areas: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    suggested_tests: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    retest_evidence_required: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    human_review_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    reviewer_decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    accepted_as_remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship("Incident")
    requested_by: Mapped["User | None"] = relationship("User", foreign_keys=[requested_by_user_id])
