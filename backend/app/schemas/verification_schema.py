from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import VerificationStatus


class FixVerificationCreate(BaseModel):
    incident_id: str
    verification_status: VerificationStatus
    checks_run: list[str] | None = None
    passed_checks: list[str] | None = None
    failed_checks: list[str] | None = None
    evidence_used: list[str] | None = None


class FixVerificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: str
    verification_status: VerificationStatus
    checks_run: list | None
    passed_checks: list | None
    failed_checks: list | None
    evidence_used: list | None
    timestamp: datetime


class VerifyFixRequest(BaseModel):
    controlled_retest_id: str | None = Field(
        default=None,
        max_length=64,
        description="Current controlled retest; omit to use the latest exact-chain retest.",
    )
    retest_evidence_ids: list[str] | None = Field(
        default=None,
        description=(
            "Fixed/retest evidence IDs. Omit or null to use all linked fixed_log/fixed_scan "
            "files; empty list means no retest evidence supplied."
        ),
    )


class VerifyFixResponse(BaseModel):
    verification_id: int
    incident_id: str
    verification_status: str
    checks_run: list[str]
    passed_checks: list[str]
    failed_checks: list[str]
    evidence_used: list[str]
    human_review_required: bool = True
    safe_summary: str
    incident_status: str
    verification_outcome_id: str | None = None
    eligible_for_learning: bool = False


class FixVerificationListResponse(BaseModel):
    incident_id: str
    verifications: list[FixVerificationRead]
    total: int
