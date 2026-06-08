"""Durable controlled-sandbox rollback ledger + hash verification."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RollbackExecution(Base):
    """One rollback attempt for a controlled implementation (idempotent by trigger)."""

    __tablename__ = "rollback_executions"
    __table_args__ = (
        UniqueConstraint(
            "implementation_id",
            "trigger",
            "trigger_reference",
            name="uq_rollback_executions_impl_trigger_ref",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rollback_execution_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    implementation_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("remediation_implementation_records.implementation_id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    patch_proposal_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("patch_proposals.patch_proposal_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    baseline_snapshot_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_hashes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    restored_hashes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    trigger: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger_reference: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    performed_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    rollback_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verification_result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    failure_reason_safe: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actor_label: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    generation: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
