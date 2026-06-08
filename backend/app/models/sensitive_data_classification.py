from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SensitiveDataClassification(Base):
    __tablename__ = "sensitive_data_classifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    classification_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    classification_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    detection_id: Mapped[str | None] = mapped_column(
        ForeignKey("detections.detection_id", ondelete="RESTRICT"), index=True, nullable=True
    )
    privacy_alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("privacy_alerts.alert_id", ondelete="RESTRICT"), index=True, nullable=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=True
    )
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence_files.evidence_id", ondelete="RESTRICT"), index=True, nullable=True
    )
    normalized_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("normalized_events.event_id", ondelete="RESTRICT"), index=True, nullable=True
    )
    affected_subject_reference_id: Mapped[str | None] = mapped_column(
        ForeignKey("affected_subject_references.subject_reference_id", ondelete="RESTRICT"),
        index=True,
        nullable=True,
    )
    taxonomy_code: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    category_group: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    detection_method: Mapped[str] = mapped_column(String(64), nullable=False)
    matched_alias: Mapped[str | None] = mapped_column(String(255), nullable=True)
    context_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    format_validation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    source_context_status: Mapped[str] = mapped_column(String(32), nullable=False)
    credential_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    document_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    masked_value: Mapped[str] = mapped_column(String(512), nullable=False)
    value_fingerprint: Mapped[str | None] = mapped_column(String(160), nullable=True)
    fingerprint_strategy: Mapped[str] = mapped_column(String(48), nullable=False)
    confidence_label: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    review_status: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False, default="pending"
    )
    internal_only: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=False)
    customer_notification_allowed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    restricted_roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_role: Mapped[str] = mapped_column(String(32), nullable=False, default="original")
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
