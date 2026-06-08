from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CustomerNotificationDecision(Base):
    __tablename__ = "customer_notification_decisions"
    __table_args__ = (UniqueConstraint("incident_id", "affected_subject_reference_id", "assessment_id", name="uq_notification_subject_assessment"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    notification_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="RESTRICT"), index=True, nullable=False)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("privacy_impact_assessments.assessment_id", ondelete="RESTRICT"), index=True, nullable=False)
    affected_subject_reference_id: Mapped[str] = mapped_column(ForeignKey("affected_subject_references.subject_reference_id", ondelete="RESTRICT"), index=True, nullable=False)
    recommendation: Mapped[str] = mapped_column(String(48), nullable=False)
    reason_codes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    decision_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="drafted", index=True)
    draft_message: Mapped[str] = mapped_column(Text, nullable=False)
    message_locale: Mapped[str] = mapped_column(String(16), nullable=False, default="en")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"
    __table_args__ = (UniqueConstraint("notification_id", "channel", name="uq_outbox_notification_channel"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    outbox_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    notification_id: Mapped[str] = mapped_column(ForeignKey("customer_notification_decisions.notification_id", ondelete="RESTRICT"), index=True, nullable=False)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    destination_reference: Mapped[str] = mapped_column(String(96), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_message_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DeliveryAttempt(Base):
    __tablename__ = "delivery_attempts"
    __table_args__ = (UniqueConstraint("outbox_id", "attempt_number", name="uq_delivery_attempt_number"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    delivery_attempt_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    outbox_id: Mapped[str] = mapped_column(ForeignKey("notification_outbox.outbox_id", ondelete="RESTRICT"), index=True, nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_message_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
