"""Counterfactual analysis, alert operations, and preventive controls.

Revision ID: 016_counterfactual_alert_prevention
Revises: 015_decision_provenance_integrity
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "016_counterfactual_alert_prevention"
down_revision: Union[str, None] = "015_decision_provenance_integrity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def _column_names(table_name: str) -> set[str]:
    if context.is_offline_mode():
        return set()
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def _table_names() -> set[str]:
    if context.is_offline_mode():
        return set()
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    op.create_table(
        "counterfactual_analyses",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("analysis_id", sa.String(64), nullable=False),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("root_cause_id", sa.String(64), nullable=False),
        sa.Column("causal_ruleset_version", sa.String(128), nullable=False),
        sa.Column("input_fingerprint", sa.String(128), nullable=False),
        sa.Column("baseline_score", sa.Float(), nullable=False),
        sa.Column("baseline_rank", sa.Integer(), nullable=False),
        sa.Column("stability_level", sa.String(32), nullable=False),
        sa.Column("fragile_conclusion", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("minimal_evidence_set", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("missing_evidence_recommendations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["root_cause_id"], ["root_cause_scores.root_cause_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("analysis_id"),
        sa.UniqueConstraint("root_cause_id", "causal_ruleset_version", "input_fingerprint", name="uq_counterfactual_idempotency"),
    )
    op.create_index("ix_counterfactual_analysis_id", "counterfactual_analyses", ["analysis_id"], unique=True)
    op.create_index("ix_counterfactual_incident_id", "counterfactual_analyses", ["incident_id"])
    op.create_index("ix_counterfactual_root_cause_id", "counterfactual_analyses", ["root_cause_id"])
    op.create_index("ix_counterfactual_stability", "counterfactual_analyses", ["stability_level"])
    op.create_index("ix_counterfactual_incident_created", "counterfactual_analyses", ["incident_id", "created_at"])

    op.create_table(
        "counterfactual_test_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("test_result_id", sa.String(64), nullable=False),
        sa.Column("analysis_id", sa.String(64), nullable=False),
        sa.Column("test_type", sa.String(32), nullable=False),
        sa.Column("evidence_id", sa.String(64), nullable=True),
        sa.Column("evidence_role", sa.String(32), nullable=False),
        sa.Column("score_before", sa.Float(), nullable=False), sa.Column("score_after", sa.Float(), nullable=False),
        sa.Column("score_change", sa.Float(), nullable=False), sa.Column("rank_before", sa.Integer(), nullable=False),
        sa.Column("rank_after", sa.Integer(), nullable=True), sa.Column("rank_changed", sa.Boolean(), nullable=False),
        sa.Column("importance_level", sa.String(32), nullable=False), sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["counterfactual_analyses.analysis_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("test_result_id"),
    )
    op.create_index("ix_counterfactual_test_id", "counterfactual_test_results", ["test_result_id"], unique=True)
    op.create_index("ix_counterfactual_test_analysis", "counterfactual_test_results", ["analysis_id"])

    existing_breach_columns = _column_names("breach_alerts")
    added_breach_columns: set[str] = set()
    for column in (
        sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("duplicate_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("assessment_version", sa.Integer(), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("source_system_grouping", sa.String(128), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("public_exposure_present", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("external_access_confirmed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("assigned_user_id", sa.Integer(), nullable=True),
        sa.Column("assigned_team", sa.String(128), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledgement_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("containment_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("escalation_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppression_type", sa.String(32), nullable=True),
        sa.Column("suppression_reason", sa.Text(), nullable=True),
        sa.Column("suppression_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppression_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppressed_by", sa.Integer(), nullable=True),
        sa.Column("escalation_level", sa.String(48), server_default="none", nullable=False),
        sa.Column("escalation_reason", sa.Text(), nullable=True),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("escalated_by", sa.Integer(), nullable=True),
        sa.Column("reopened_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopened_by", sa.Integer(), nullable=True),
        sa.Column("reopen_reason", sa.Text(), nullable=True),
    ):
        if column.name not in existing_breach_columns:
            op.add_column("breach_alerts", column)
            added_breach_columns.add(column.name)
    for name, local in (
        ("fk_breach_alert_assigned_user", "assigned_user_id"), ("fk_breach_alert_suppressed_by", "suppressed_by"),
        ("fk_breach_alert_escalated_by", "escalated_by"), ("fk_breach_alert_reopened_by", "reopened_by"),
    ):
        if local in added_breach_columns:
            op.create_foreign_key(name, "breach_alerts", "users", [local], ["id"], ondelete="SET NULL")
    for name, columns in (
        ("ix_breach_alert_assigned_user", ["assigned_user_id"]), ("ix_breach_alert_ack_deadline", ["acknowledgement_deadline"]),
        ("ix_breach_alert_containment_deadline", ["containment_deadline"]), ("ix_breach_alert_escalation_deadline", ["escalation_deadline"]),
        ("ix_breach_alert_suppression_expires", ["suppression_expires_at"]), ("ix_breach_alert_escalation_level", ["escalation_level"]),
    ):
        if all(column in added_breach_columns for column in columns):
            op.create_index(name, "breach_alerts", columns)

    if "breach_alert_evidence_links" not in _table_names():
        op.create_table(
            "breach_alert_evidence_links",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("alert_id", sa.String(64), nullable=False), sa.Column("evidence_id", sa.String(64), nullable=False),
            sa.Column("linked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["alert_id"], ["breach_alerts.alert_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["evidence_id"], ["evidence_files.evidence_id"], ondelete="RESTRICT"),
            sa.UniqueConstraint("alert_id", "evidence_id", name="uq_breach_alert_evidence"),
        )
        op.create_index("ix_breach_alert_evidence_alert", "breach_alert_evidence_links", ["alert_id"])
        op.create_index("ix_breach_alert_evidence_evidence", "breach_alert_evidence_links", ["evidence_id"])

    op.create_table(
        "preventive_controls",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(64), nullable=False), sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("root_cause_id", sa.String(64), nullable=False), sa.Column("decision_record_id", sa.String(64), nullable=True),
        sa.Column("remediation_action_id", sa.String(64), nullable=True), sa.Column("control_type", sa.String(48), nullable=False),
        sa.Column("control_name", sa.String(255), nullable=False), sa.Column("control_description", sa.Text(), nullable=False),
        sa.Column("generated_content", sa.Text(), nullable=False), sa.Column("language", sa.String(48), nullable=True),
        sa.Column("status", sa.String(32), server_default="proposed", nullable=False), sa.Column("source", sa.String(48), nullable=False),
        sa.Column("generation_method", sa.String(96), nullable=False), sa.Column("ruleset_version", sa.String(64), nullable=False),
        sa.Column("requires_human_review", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True), sa.Column("reviewed_by", sa.Integer(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True), sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True), sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("implementation_reference", sa.String(512), nullable=True), sa.Column("implemented_by", sa.Integer(), nullable=True),
        sa.Column("implemented_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_status", sa.String(32), server_default="not_started", nullable=False),
        sa.Column("verification_method", sa.String(128), nullable=True), sa.Column("verification_result", sa.Text(), nullable=True),
        sa.Column("verified_by", sa.Integer(), nullable=True), sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True), sa.Column("supersedes_control_id", sa.String(64), nullable=True),
        sa.Column("retired_by", sa.Integer(), nullable=True), sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retirement_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["root_cause_id"], ["root_cause_scores.root_cause_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["decision_record_id"], ["breach_decision_records.decision_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["remediation_action_id"], ["remediation_actions.remediation_action_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["supersedes_control_id"], ["preventive_controls.control_id"], ondelete="RESTRICT"),
        *[sa.ForeignKeyConstraint([name], ["users.id"], ondelete="SET NULL") for name in ("created_by", "reviewed_by", "approved_by", "implemented_by", "verified_by", "retired_by")],
        sa.UniqueConstraint("control_id"),
    )
    op.create_index("ix_preventive_control_id", "preventive_controls", ["control_id"], unique=True)
    for name, columns in (
        ("ix_preventive_control_incident", ["incident_id"]), ("ix_preventive_control_root_cause", ["root_cause_id"]),
        ("ix_preventive_control_decision", ["decision_record_id"]), ("ix_preventive_control_type", ["control_type"]),
        ("ix_preventive_control_status", ["status"]), ("ix_preventive_control_verification", ["verification_status"]),
    ):
        op.create_index(name, "preventive_controls", columns)

    op.create_table(
        "preventive_control_evidence_links",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(64), nullable=False), sa.Column("evidence_id", sa.String(64), nullable=False),
        sa.Column("evidence_role", sa.String(32), server_default="retest", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["control_id"], ["preventive_controls.control_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_files.evidence_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("control_id", "evidence_id", "evidence_role", name="uq_control_evidence_role"),
    )
    op.create_index("ix_preventive_control_evidence_control", "preventive_control_evidence_links", ["control_id"])
    op.create_index("ix_preventive_control_evidence_evidence", "preventive_control_evidence_links", ["evidence_id"])


def downgrade() -> None:
    tables = _table_names()
    offline = context.is_offline_mode()
    for table in ("preventive_control_evidence_links", "preventive_controls", "breach_alert_evidence_links"):
        if offline or table in tables:
            op.drop_table(table)
    index_names = set() if offline else {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("breach_alerts")}
    for name in (
        "ix_breach_alert_escalation_level", "ix_breach_alert_suppression_expires", "ix_breach_alert_escalation_deadline",
        "ix_breach_alert_containment_deadline", "ix_breach_alert_ack_deadline", "ix_breach_alert_assigned_user",
    ):
        if offline or name in index_names:
            op.drop_index(name, table_name="breach_alerts")
    foreign_keys = set() if offline else {item["name"] for item in sa.inspect(op.get_bind()).get_foreign_keys("breach_alerts")}
    for name in ("fk_breach_alert_reopened_by", "fk_breach_alert_escalated_by", "fk_breach_alert_suppressed_by", "fk_breach_alert_assigned_user"):
        if offline or name in foreign_keys:
            op.drop_constraint(name, "breach_alerts", type_="foreignkey")
    columns = _column_names("breach_alerts")
    for name in (
        "reopen_reason", "reopened_by", "reopened_at", "reopened_count", "escalated_by", "escalated_at", "escalation_reason",
        "escalation_level", "suppressed_by", "suppression_expires_at", "suppression_started_at", "suppression_reason",
        "suppression_type", "escalation_deadline", "containment_deadline", "acknowledgement_deadline", "assigned_at",
        "assigned_team", "assigned_user_id", "external_access_confirmed", "public_exposure_present", "last_observed_at",
        "source_system_grouping", "policy_version", "assessment_version", "duplicate_count", "occurrence_count",
    ):
        if offline or name in columns:
            op.drop_column("breach_alerts", name)
    for table in ("counterfactual_test_results", "counterfactual_analyses"):
        if offline or table in tables:
            op.drop_table(table)
