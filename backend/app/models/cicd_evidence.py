from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class CicdEvidence(Base):
    __tablename__ = "cicd_evidence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cicd_evidence_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    pipeline_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    deployment_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    commit_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    changed_file_paths_safe: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    change_categories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    scan_summary_safe: Mapped[str | None] = mapped_column(Text, nullable=True)
    test_summary_safe: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    raw_event_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    linked_incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False, default="safe")

    incident: Mapped["Incident | None"] = relationship(
        "Incident", back_populates="cicd_evidence"
    )
