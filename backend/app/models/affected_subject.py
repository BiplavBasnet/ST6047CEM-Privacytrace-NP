from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AffectedSubjectReference(Base):
    __tablename__ = "affected_subject_references"
    __table_args__ = (UniqueConstraint("incident_id", "subject_reference", name="uq_affected_subject_incident_reference"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    subject_reference_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False)
    subject_reference: Mapped[str] = mapped_column(String(96), nullable=False)
    reference_method: Mapped[str] = mapped_column(String(32), nullable=False, default="hmac_sha256_v1")
    subject_type: Mapped[str] = mapped_column(String(48), nullable=False, default="unknown_subject_type", index=True)
    resolution_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unresolved", index=True)
    affected_data_categories: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    credential_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    notification_eligibility: Mapped[str] = mapped_column(String(32), nullable=False, default="not_assessed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
