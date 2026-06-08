"""Workflow provenance, verification integrity, and operational hardening.

Revision ID: 025_workflow_provenance_hardening
Revises: 024_verified_remediation_completion
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "025_workflow_provenance_hardening"
down_revision: Union[str, None] = "024_verified_remediation_completion"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _cols(inspector, table: str) -> set[str]:
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "root_cause_analyses" not in tables:
        op.create_table(
            "root_cause_analyses",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("analysis_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("analysis_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("rules_version", sa.String(length=128), nullable=True),
            sa.Column("taxonomy_version", sa.String(length=64), nullable=True),
            sa.Column("exposure_policy_version", sa.String(length=64), nullable=True),
            sa.Column("evidence_snapshot_hash", sa.String(length=128), nullable=False),
            sa.Column("evidence_revision", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("analysed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("stale", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("stale_reason", sa.Text(), nullable=True),
            sa.Column("superseded_by_analysis_id", sa.String(length=64), nullable=True),
            sa.Column("current", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("analysis_id"),
        )
        op.create_index("ix_root_cause_analyses_analysis_id", "root_cause_analyses", ["analysis_id"])
        op.create_index("ix_root_cause_analyses_incident_id", "root_cause_analyses", ["incident_id"])
        op.create_index(
            "ix_root_cause_analyses_incident_current",
            "root_cause_analyses",
            ["incident_id", "current"],
        )

    # Backfill from existing score batches.
    op.execute(
        sa.text(
            """
            INSERT INTO root_cause_analyses (
                analysis_id, incident_id, analysis_version, rules_version,
                evidence_snapshot_hash, analysed_at, stale, stale_reason,
                superseded_by_analysis_id, current
            )
            SELECT DISTINCT ON (analysis_id)
                analysis_id,
                incident_id,
                COALESCE(analysis_version, 1),
                rules_version,
                COALESCE(evidence_snapshot_hash, 'legacy-unknown'),
                analysed_at,
                COALESCE(stale, false),
                stale_reason,
                superseded_by_analysis_id,
                CASE WHEN COALESCE(stale, false) = false
                     AND superseded_by_analysis_id IS NULL THEN true ELSE false END
            FROM root_cause_scores
            WHERE analysis_id IS NOT NULL
            ORDER BY analysis_id, analysed_at DESC NULLS LAST
            ON CONFLICT (analysis_id) DO NOTHING
            """
        )
    )

    rd_cols = _cols(inspector, "review_decisions")
    if "root_cause_analysis_id" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("root_cause_analysis_id", sa.String(length=64), nullable=True),
        )
        op.create_index(
            "ix_review_decisions_root_cause_analysis_id",
            "review_decisions",
            ["root_cause_analysis_id"],
        )
    if "root_cause_analysis_version" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("root_cause_analysis_version", sa.Integer(), nullable=True),
        )
    if "evidence_snapshot_hash" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("evidence_snapshot_hash", sa.String(length=128), nullable=True),
        )
    if "limitations_acknowledged" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("limitations_acknowledged", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    if "progression_valid" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("progression_valid", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        )
    if "progression_invalid_reason" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("progression_invalid_reason", sa.Text(), nullable=True),
        )
    if "submitted_at" not in rd_cols:
        op.add_column(
            "review_decisions",
            sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Bind legacy reviews to current analysis where possible (best-effort).
    op.execute(
        sa.text(
            """
            UPDATE review_decisions rd
            SET root_cause_analysis_id = rca.analysis_id,
                root_cause_analysis_version = rca.analysis_version,
                evidence_snapshot_hash = rca.evidence_snapshot_hash,
                submitted_at = COALESCE(rd.submitted_at, rd.timestamp)
            FROM root_cause_analyses rca
            WHERE rd.incident_id = rca.incident_id
              AND rca.current = true
              AND rd.root_cause_analysis_id IS NULL
            """
        )
    )

    diag_cols = _cols(inspector, "remediation_diagnoses")
    for name, col in [
        ("root_cause_analysis_version", sa.Column("root_cause_analysis_version", sa.Integer(), nullable=True)),
        ("review_decision_id", sa.Column("review_decision_id", sa.Integer(), nullable=True)),
        ("generation_mode", sa.Column("generation_mode", sa.String(length=64), nullable=True)),
        ("playbook_id", sa.Column("playbook_id", sa.String(length=64), nullable=True)),
        ("playbook_version", sa.Column("playbook_version", sa.String(length=64), nullable=True)),
        ("ai_failure_type", sa.Column("ai_failure_type", sa.String(length=128), nullable=True)),
        ("fallback_mode", sa.Column("fallback_mode", sa.String(length=64), nullable=True)),
        ("derived_from_stale_analysis", sa.Column("derived_from_stale_analysis", sa.Boolean(), nullable=False, server_default=sa.text("false"))),
        ("workflow_status", sa.Column("workflow_status", sa.String(length=64), nullable=False, server_default="current")),
    ]:
        if name not in diag_cols:
            op.add_column("remediation_diagnoses", col)

    ra_cols = _cols(inspector, "remediation_actions")
    for name, col in [
        ("diagnosis_id", sa.Column("diagnosis_id", sa.String(length=64), nullable=True)),
        ("root_cause_analysis_id", sa.Column("root_cause_analysis_id", sa.String(length=64), nullable=True)),
        ("review_decision_id", sa.Column("review_decision_id", sa.Integer(), nullable=True)),
        ("approved_payload_version", sa.Column("approved_payload_version", sa.Integer(), nullable=False, server_default="1")),
        ("approved_problem_statement", sa.Column("approved_problem_statement", sa.Text(), nullable=True)),
        ("approved_change", sa.Column("approved_change", sa.Text(), nullable=True)),
        ("affected_service", sa.Column("affected_service", sa.String(length=255), nullable=True)),
        ("affected_endpoint", sa.Column("affected_endpoint", sa.String(length=512), nullable=True)),
        ("affected_file", sa.Column("affected_file", sa.String(length=1024), nullable=True)),
        ("affected_function", sa.Column("affected_function", sa.String(length=255), nullable=True)),
        ("affected_configuration", sa.Column("affected_configuration", sa.String(length=255), nullable=True)),
        ("implementation_steps", sa.Column("implementation_steps", postgresql.JSONB(astext_type=sa.Text()), nullable=True)),
        ("required_tests", sa.Column("required_tests", postgresql.JSONB(astext_type=sa.Text()), nullable=True)),
        ("retest_requirements", sa.Column("retest_requirements", postgresql.JSONB(astext_type=sa.Text()), nullable=True)),
        ("risks", sa.Column("risks", sa.Text(), nullable=True)),
        ("rollback_plan", sa.Column("rollback_plan", sa.Text(), nullable=True)),
        ("implementation_mode", sa.Column("implementation_mode", sa.String(length=64), nullable=True)),
        ("approved_by", sa.Column("approved_by", sa.Integer(), nullable=True)),
        ("approved_at", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True)),
        ("requires_revalidation", sa.Column("requires_revalidation", sa.Boolean(), nullable=False, server_default=sa.text("false"))),
        ("idempotency_key", sa.Column("idempotency_key", sa.String(length=128), nullable=True)),
    ]:
        if name not in ra_cols:
            op.add_column("remediation_actions", col)
    if "idempotency_key" not in ra_cols:
        op.create_index(
            "uq_remediation_actions_idempotency",
            "remediation_actions",
            ["idempotency_key"],
            unique=True,
            postgresql_where=sa.text("idempotency_key IS NOT NULL"),
        )

    pp_cols = _cols(inspector, "patch_proposals")
    for name, col in [
        ("root_cause_analysis_id", sa.Column("root_cause_analysis_id", sa.String(length=64), nullable=True)),
        ("base_source_hash", sa.Column("base_source_hash", sa.String(length=128), nullable=True)),
        ("post_apply_workspace_hash", sa.Column("post_apply_workspace_hash", sa.String(length=128), nullable=True)),
        ("pre_test_workspace_hash", sa.Column("pre_test_workspace_hash", sa.String(length=128), nullable=True)),
        ("workspace_integrity_status", sa.Column("workspace_integrity_status", sa.String(length=64), nullable=True)),
        ("last_known_state", sa.Column("last_known_state", sa.String(length=64), nullable=True)),
        (
            "recovery_required",
            sa.Column("recovery_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        ),
    ]:
        if name not in pp_cols:
            op.add_column("patch_proposals", col)

    if "remediation_test_executions" not in tables:
        op.create_table(
            "remediation_test_executions",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("execution_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("remediation_action_id", sa.String(length=64), nullable=True),
            sa.Column("patch_proposal_id", sa.String(length=64), nullable=True),
            sa.Column("implementation_mode", sa.String(length=64), nullable=True),
            sa.Column("workspace_reference_safe", sa.String(length=1024), nullable=True),
            sa.Column("workspace_hash", sa.String(length=128), nullable=True),
            sa.Column("test_profile", sa.String(length=128), nullable=False),
            sa.Column("command_profile_version", sa.String(length=64), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("exit_code", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("test_count", sa.Integer(), nullable=True),
            sa.Column("passed_count", sa.Integer(), nullable=True),
            sa.Column("failed_count", sa.Integer(), nullable=True),
            sa.Column("raw_leakage_count", sa.Integer(), nullable=True),
            sa.Column("safe_output_summary", sa.Text(), nullable=True),
            sa.Column("safety_status", sa.String(length=64), nullable=True),
            sa.Column("executed_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("execution_id"),
        )
        op.create_index("ix_remediation_test_executions_incident_id", "remediation_test_executions", ["incident_id"])

    if "exposure_verification_profiles" not in tables:
        op.create_table(
            "exposure_verification_profiles",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("profile_id", sa.String(length=64), nullable=False),
            sa.Column("original_finding_id", sa.String(length=128), nullable=True),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("sensitive_type", sa.String(length=128), nullable=True),
            sa.Column("sensitivity_level", sa.String(length=64), nullable=True),
            sa.Column("exposure_location", sa.String(length=128), nullable=True),
            sa.Column("service_name", sa.String(length=255), nullable=True),
            sa.Column("endpoint", sa.String(length=512), nullable=True),
            sa.Column("environment", sa.String(length=128), nullable=True),
            sa.Column("component", sa.String(length=255), nullable=True),
            sa.Column("field_name_safe", sa.String(length=255), nullable=True),
            sa.Column("trace_correlation_context", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("deployment_version", sa.String(length=128), nullable=True),
            sa.Column("relevant_policy_id", sa.String(length=128), nullable=True),
            sa.Column("original_finding_hash", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("profile_id"),
        )

    if "verification_outcomes" not in tables:
        op.create_table(
            "verification_outcomes",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("verification_outcome_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("root_cause_analysis_id", sa.String(length=64), nullable=True),
            sa.Column("review_decision_id", sa.Integer(), nullable=True),
            sa.Column("remediation_diagnosis_id", sa.String(length=64), nullable=True),
            sa.Column("remediation_action_id", sa.String(length=64), nullable=True),
            sa.Column("patch_proposal_id", sa.String(length=64), nullable=True),
            sa.Column("test_execution_id", sa.String(length=64), nullable=True),
            sa.Column("original_exposure_finding_id", sa.String(length=128), nullable=True),
            sa.Column("retest_finding_id", sa.String(length=128), nullable=True),
            sa.Column("fix_verification_id", sa.Integer(), nullable=True),
            sa.Column("implementation_mode", sa.String(length=64), nullable=True),
            sa.Column("same_service_match", sa.Boolean(), nullable=True),
            sa.Column("same_endpoint_match", sa.Boolean(), nullable=True),
            sa.Column("same_exposure_location_match", sa.Boolean(), nullable=True),
            sa.Column("same_sensitive_type_match", sa.Boolean(), nullable=True),
            sa.Column("same_component_match", sa.Boolean(), nullable=True),
            sa.Column("tests_passed", sa.Boolean(), nullable=True),
            sa.Column("raw_exposure_after_change", sa.Boolean(), nullable=True),
            sa.Column("verification_result", sa.String(length=64), nullable=False),
            sa.Column("limitations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("verified_by", sa.String(length=255), nullable=True),
            sa.Column("verified_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("eligible_for_learning", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("eligibility_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("verification_outcome_id"),
        )
        op.create_index("ix_verification_outcomes_incident_id", "verification_outcomes", ["incident_id"])

    if "alert_trace_references" not in tables:
        op.create_table(
            "alert_trace_references",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("alert_id", sa.String(length=64), nullable=False),
            sa.Column("trace_fingerprint", sa.String(length=128), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("alert_id", "trace_fingerprint", name="uq_alert_trace_fingerprint"),
        )
        op.create_index("ix_alert_trace_references_alert_id", "alert_trace_references", ["alert_id"])

    # Learning semantic fix marker columns (canonical fields already exist).
    vrc_cols = _cols(inspector, "verified_remediation_cases")
    if "verification_outcome_id" not in vrc_cols:
        op.add_column(
            "verified_remediation_cases",
            sa.Column("verification_outcome_id", sa.String(length=64), nullable=True),
        )
    if "semantics_version" not in vrc_cols:
        op.add_column(
            "verified_remediation_cases",
            sa.Column("semantics_version", sa.String(length=32), nullable=False, server_default="v2"),
        )

    # Time quality on normalized_events
    ne_cols = _cols(inspector, "normalized_events")
    for name, col in [
        ("event_time_source", sa.Column("event_time_source", sa.String(length=64), nullable=True)),
        ("time_quality", sa.Column("time_quality", sa.String(length=64), nullable=True)),
        ("time_inferred", sa.Column("time_inferred", sa.Boolean(), nullable=False, server_default=sa.text("false"))),
        ("timezone_name", sa.Column("timezone_name", sa.String(length=64), nullable=True)),
    ]:
        if name not in ne_cols:
            op.add_column("normalized_events", col)

    # Report versioning columns
    report_cols = _cols(inspector, "reports")
    for name, col in [
        ("report_version", sa.Column("report_version", sa.Integer(), nullable=False, server_default="1")),
        ("root_cause_analysis_id", sa.Column("root_cause_analysis_id", sa.String(length=64), nullable=True)),
        ("evidence_snapshot_hash", sa.Column("evidence_snapshot_hash", sa.String(length=128), nullable=True)),
        ("review_decision_id", sa.Column("review_decision_id", sa.Integer(), nullable=True)),
        ("remediation_diagnosis_id", sa.Column("remediation_diagnosis_id", sa.String(length=64), nullable=True)),
        ("remediation_action_id", sa.Column("remediation_action_id", sa.String(length=64), nullable=True)),
        ("patch_proposal_id", sa.Column("patch_proposal_id", sa.String(length=64), nullable=True)),
        ("test_execution_id", sa.Column("test_execution_id", sa.String(length=64), nullable=True)),
        ("verification_outcome_id", sa.Column("verification_outcome_id", sa.String(length=64), nullable=True)),
        ("recommendation_policy_version", sa.Column("recommendation_policy_version", sa.String(length=64), nullable=True)),
    ]:
        if name not in report_cols:
            op.add_column("reports", col)

    # Audit chain hashes (optional)
    audit_cols = _cols(inspector, "audit_logs")
    if "previous_entry_hash" not in audit_cols:
        op.add_column("audit_logs", sa.Column("previous_entry_hash", sa.String(length=128), nullable=True))
    if "entry_hash" not in audit_cols:
        op.add_column("audit_logs", sa.Column("entry_hash", sa.String(length=128), nullable=True))


def downgrade() -> None:
    # Non-destructive downgrade omitted for Bachelor prototype safety.
    pass
