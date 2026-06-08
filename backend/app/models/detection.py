from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.evidence_file import EvidenceFile
    from app.models.incident import Incident


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    detection_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="SET NULL"),
        nullable=True,
    )
    normalized_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("normalized_events.event_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    sensitive_type: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_value_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    masked_value: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="detection_severity", native_enum=False),
        nullable=True,
    )
    detector_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="detections")
    evidence_file: Mapped["EvidenceFile | None"] = relationship("EvidenceFile")
