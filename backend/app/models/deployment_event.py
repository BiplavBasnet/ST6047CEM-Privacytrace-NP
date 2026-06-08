from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile


class DeploymentEvent(Base):
    __tablename__ = "deployment_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    release_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deployment_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    config_changes: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_level: Mapped[str | None] = mapped_column(String(64), nullable=True)

    evidence_file: Mapped["EvidenceFile"] = relationship(
        "EvidenceFile",
        back_populates="deployment_events",
    )
