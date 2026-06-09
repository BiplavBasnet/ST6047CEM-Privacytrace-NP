from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IntegrityLedgerRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    integrity_record_id: str
    sequence_number: int
    record_type: str
    record_id: str
    scope_type: str | None
    scope_id: str | None
    content_hash: str
    previous_record_hash: str | None
    record_hash: str
    integrity_schema_version: str
    created_at: datetime
    verification_status: str
    last_verified_at: datetime | None


class IntegrityVerifyRequest(BaseModel):
    scope_type: str = Field(default="global", min_length=1, max_length=32)
    scope_id: str | None = Field(default=None, max_length=128)


class IntegrityVerificationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    verification_run_id: str
    scope_type: str
    scope_id: str | None
    records_checked: int
    scope_records_checked: int
    verified_head_sequence: int | None
    verified_head_hash: str | None
    failure_fingerprint: str | None
    integrity_alert_id: str | None
    chain_valid: bool
    content_mismatch_count: int
    missing_sequence_count: int
    invalid_link_count: int
    first_invalid_sequence: int | None
    result_summary: str
    started_at: datetime
    completed_at: datetime | None
    executed_by: int | None


class IntegrityStatusResponse(BaseModel):
    scope_type: str
    scope_id: str | None
    status: str
    last_verification: IntegrityVerificationRunRead | None
    records: list[IntegrityLedgerRecordRead] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
