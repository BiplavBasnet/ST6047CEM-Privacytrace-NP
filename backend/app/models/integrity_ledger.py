from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IntegrityLedgerHead(Base):
    __tablename__ = "integrity_ledger_head"
    __table_args__ = (CheckConstraint("id = 1", name="ck_integrity_ledger_head_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    last_sequence_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_record_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class IntegrityLedgerRecord(Base):
    __tablename__ = "integrity_ledger_records"
    __table_args__ = (
        UniqueConstraint("sequence_number", name="uq_integrity_ledger_sequence"),
        UniqueConstraint("record_hash", name="uq_integrity_ledger_record_hash"),
        UniqueConstraint("record_type", "record_id", "content_hash", name="uq_integrity_ledger_content"),
        Index("ix_integrity_ledger_record", "record_type", "record_id"),
        Index("ix_integrity_ledger_scope", "scope_type", "scope_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    integrity_record_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    record_type: Mapped[str] = mapped_column(String(64), nullable=False)
    record_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scope_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scope_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    previous_record_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    record_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    integrity_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_yet_verified", index=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IntegrityVerificationRun(Base):
    __tablename__ = "integrity_verification_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    verification_run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scope_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    records_checked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scope_records_checked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verified_head_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verified_head_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    failure_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    integrity_alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("privacy_alerts.alert_id", ondelete="SET NULL"), nullable=True
    )
    chain_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    content_mismatch_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    missing_sequence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    invalid_link_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_invalid_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verification_mode: Mapped[str] = mapped_column(
        String(64), nullable=False, default="global_with_scope_membership"
    )
    result_summary: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
