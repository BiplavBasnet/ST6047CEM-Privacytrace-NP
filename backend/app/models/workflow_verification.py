"""Persisted remediation test execution and verification outcome entities."""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RemediationImplementationRecord(Base):
    """Human-attributable implementation of one approved remediation action."""

    __tablename__ = "remediation_implementation_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    implementation_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    root_cause_analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"), nullable=False)
    review_decision_id: Mapped[int] = mapped_column(Integer, ForeignKey("review_decisions.id", ondelete="RESTRICT"), nullable=False)
    diagnosis_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediation_diagnoses.diagnosis_id", ondelete="RESTRICT"), nullable=False)
    remediation_action_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediation_actions.remediation_action_id", ondelete="RESTRICT"), nullable=False, index=True)
    patch_proposal_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("patch_proposals.patch_proposal_id", ondelete="RESTRICT"), nullable=True)
    implementation_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    change_reference_safe: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    change_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    implementation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="completed")
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    implemented_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    implemented_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RemediationTestExecution(Base):
    __tablename__ = "remediation_test_executions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    execution_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    patch_proposal_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    implementation_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_implementation_records.implementation_id", ondelete="RESTRICT"), nullable=True, index=True)
    implementation_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    workspace_reference_safe: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    workspace_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    test_profile: Mapped[str] = mapped_column(String(128), nullable=False)
    command_profile_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    test_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    passed_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failed_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_leakage_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    safe_output_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    safety_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ExposureVerificationProfile(Base):
    __tablename__ = "exposure_verification_profiles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    profile_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    original_finding_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=False
    )
    sensitive_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sensitivity_level: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exposure_location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(128), nullable=True)
    component: Mapped[str | None] = mapped_column(String(255), nullable=True)
    field_name_safe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    trace_correlation_context: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    deployment_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    relevant_policy_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    original_finding_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class VerificationOutcome(Base):
    __tablename__ = "verification_outcomes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    verification_outcome_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    root_cause_analysis_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_decision_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remediation_diagnosis_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    patch_proposal_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    test_execution_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    implementation_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("remediation_implementation_records.implementation_id", ondelete="RESTRICT"), nullable=True)
    controlled_retest_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("controlled_retests.controlled_retest_id", ondelete="RESTRICT"), nullable=True)
    original_exposure_finding_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    retest_finding_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fix_verification_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    implementation_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    same_service_match: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    same_endpoint_match: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    same_exposure_location_match: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    same_sensitive_type_match: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    same_component_match: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tests_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    raw_exposure_after_change: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verification_result: Mapped[str] = mapped_column(String(64), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    verified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    eligible_for_learning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    eligibility_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ControlledRetest(Base):
    """Explicit controlled reproduction tied to one implementation and test run."""

    __tablename__ = "controlled_retests"
    __table_args__ = (
        UniqueConstraint(
            "implementation_id", "test_execution_id", name="uq_controlled_retest_implementation_test"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    controlled_retest_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    root_cause_analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("root_cause_analyses.analysis_id", ondelete="RESTRICT"), nullable=False)
    review_decision_id: Mapped[int] = mapped_column(Integer, ForeignKey("review_decisions.id", ondelete="RESTRICT"), nullable=False)
    diagnosis_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediation_diagnoses.diagnosis_id", ondelete="RESTRICT"), nullable=False)
    remediation_action_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediation_actions.remediation_action_id", ondelete="RESTRICT"), nullable=False)
    implementation_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediation_implementation_records.implementation_id", ondelete="RESTRICT"), nullable=False, index=True)
    test_execution_id: Mapped[str] = mapped_column(String(64), ForeignKey("remediation_test_executions.execution_id", ondelete="RESTRICT"), nullable=False)
    original_finding_id: Mapped[str] = mapped_column(String(128), ForeignKey("detections.detection_id", ondelete="RESTRICT"), nullable=False)
    retest_finding_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    exposure_location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sensitive_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    component: Mapped[str | None] = mapped_column(String(255), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dimensions_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    required_dimensions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    missing_dimensions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    raw_exposure_after_change: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    safe_findings: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    safety_status: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    workflow_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="current", server_default="current"
    )
    invalidation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AlertTraceReference(Base):
    __tablename__ = "alert_trace_references"
    __table_args__ = (
        UniqueConstraint("alert_id", "trace_fingerprint", name="uq_alert_trace_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    trace_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_method: Mapped[str] = mapped_column(String(32), nullable=False)
    fingerprint_version: Mapped[str] = mapped_column(String(16), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
