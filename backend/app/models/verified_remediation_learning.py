from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

if TYPE_CHECKING:
    pass


class PatchProposal(Base):
    """Persisted controlled patch proposal — sandbox only, never production."""

    __tablename__ = "patch_proposals"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    patch_proposal_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    diagnosis_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    root_cause_analysis_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    repository_reference_safe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String(128), nullable=True)
    temporary_workspace: Mapped[str] = mapped_column(String(1024), nullable=False)
    temporary_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_files: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    patch_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    safe_diff: Mapped[str] = mapped_column(Text, nullable=False)
    safety_result: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")
    status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    human_approval_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rollback_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    base_source_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    post_apply_workspace_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    pre_test_workspace_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    workspace_integrity_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_known_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recovery_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class VerifiedRemediationCase(Base):
    """Durable verified remediation outcome for ranking — PostgreSQL-backed."""

    __tablename__ = "verified_remediation_cases"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    verified_case_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    diagnosis_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    patch_proposal_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sensitive_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exposure_location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    root_cause_category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    affected_component: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_type: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    remediation_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    approved_remediation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    implementation_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tests_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verification_result: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    verified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    eligible_for_learning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    eligibility_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False, default="playbook-v1")
    verification_outcome_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    semantics_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v2")
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RemediationPlaybook(Base):
    """Durable playbook ranking counters — survives process restart."""

    __tablename__ = "remediation_playbooks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    playbook_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    root_cause_category: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    exposure_locations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    sensitive_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    component_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_pattern: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    remediation_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    test_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    retest_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verified_failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inconclusive_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="1")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
