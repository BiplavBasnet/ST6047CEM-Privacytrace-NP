"""First-class implementation, controlled retest, and exact verification chain.

Revision ID: 028_controlled_retest_verification
Revises: 027_lifecycle_integrity_foundation
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "028_controlled_retest_verification"
down_revision: Union[str, None] = "027_lifecycle_integrity_foundation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("Migration 028 requires PostgreSQL.")
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "remediation_implementation_records" not in tables:
        op.create_table(
            "remediation_implementation_records",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("implementation_id", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("root_cause_analysis_id", sa.String(64), nullable=False),
            sa.Column("review_decision_id", sa.Integer(), nullable=False),
            sa.Column("diagnosis_id", sa.String(64), nullable=False),
            sa.Column("remediation_action_id", sa.String(64), nullable=False),
            sa.Column("patch_proposal_id", sa.String(64), nullable=True),
            sa.Column("implementation_mode", sa.String(64), nullable=False),
            sa.Column("change_reference_safe", sa.String(1024), nullable=True),
            sa.Column("change_hash", sa.String(128), nullable=True),
            sa.Column("implementation_summary", sa.Text(), nullable=False),
            sa.Column("status", sa.String(64), nullable=False),
            sa.Column("idempotency_key", sa.String(160), nullable=False),
            sa.Column("implemented_by_user_id", sa.Integer(), nullable=True),
            sa.Column("implemented_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("workflow_status", sa.String(64), nullable=False, server_default="current"),
            sa.Column("invalidation_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["root_cause_analysis_id"], ["root_cause_analyses.analysis_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["review_decision_id"], ["review_decisions.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["diagnosis_id"], ["remediation_diagnoses.diagnosis_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["remediation_action_id"], ["remediation_actions.remediation_action_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["patch_proposal_id"], ["patch_proposals.patch_proposal_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["implemented_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("implementation_id"),
            sa.UniqueConstraint("idempotency_key"),
        )
        op.create_index("ix_implementation_incident", "remediation_implementation_records", ["incident_id"])
        op.create_index("ix_implementation_action", "remediation_implementation_records", ["remediation_action_id"])

    test_columns = {column["name"] for column in inspector.get_columns("remediation_test_executions")}
    if "implementation_id" not in test_columns:
        op.add_column("remediation_test_executions", sa.Column("implementation_id", sa.String(64), nullable=True))
        op.create_index("ix_test_execution_implementation", "remediation_test_executions", ["implementation_id"])
        op.create_foreign_key(
            "fk_test_execution_implementation_028",
            "remediation_test_executions",
            "remediation_implementation_records",
            ["implementation_id"],
            ["implementation_id"],
            ondelete="RESTRICT",
        )

    if "controlled_retests" not in tables:
        op.create_table(
            "controlled_retests",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("controlled_retest_id", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("root_cause_analysis_id", sa.String(64), nullable=False),
            sa.Column("review_decision_id", sa.Integer(), nullable=False),
            sa.Column("diagnosis_id", sa.String(64), nullable=False),
            sa.Column("remediation_action_id", sa.String(64), nullable=False),
            sa.Column("implementation_id", sa.String(64), nullable=False),
            sa.Column("test_execution_id", sa.String(64), nullable=False),
            sa.Column("original_finding_id", sa.String(128), nullable=False),
            sa.Column("retest_finding_id", sa.String(128), nullable=True),
            sa.Column("service_name", sa.String(255), nullable=True),
            sa.Column("endpoint", sa.String(512), nullable=True),
            sa.Column("exposure_location", sa.String(128), nullable=True),
            sa.Column("sensitive_type", sa.String(128), nullable=True),
            sa.Column("component", sa.String(255), nullable=True),
            sa.Column("environment", sa.String(128), nullable=True),
            sa.Column("dimensions_match", sa.Boolean(), nullable=False),
            sa.Column("raw_exposure_after_change", sa.Boolean(), nullable=True),
            sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("safe_findings", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
            sa.Column("safety_status", sa.String(64), nullable=False),
            sa.Column("status", sa.String(64), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("workflow_status", sa.String(64), nullable=False, server_default="current"),
            sa.Column("invalidation_reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["root_cause_analysis_id"], ["root_cause_analyses.analysis_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["review_decision_id"], ["review_decisions.id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["diagnosis_id"], ["remediation_diagnoses.diagnosis_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["remediation_action_id"], ["remediation_actions.remediation_action_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["implementation_id"], ["remediation_implementation_records.implementation_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["test_execution_id"], ["remediation_test_executions.execution_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["original_finding_id"], ["detections.detection_id"], ondelete="RESTRICT"),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("controlled_retest_id"),
            sa.UniqueConstraint("implementation_id", "test_execution_id", name="uq_controlled_retest_implementation_test"),
        )
        op.create_index("ix_controlled_retest_incident", "controlled_retests", ["incident_id"])

    fix_columns = {column["name"] for column in inspector.get_columns("fix_verifications")}
    for name, column in (
        ("root_cause_analysis_id", sa.Column("root_cause_analysis_id", sa.String(64), nullable=True)),
        ("review_decision_id", sa.Column("review_decision_id", sa.Integer(), nullable=True)),
        ("remediation_diagnosis_id", sa.Column("remediation_diagnosis_id", sa.String(64), nullable=True)),
        ("remediation_action_id", sa.Column("remediation_action_id", sa.String(64), nullable=True)),
        ("implementation_id", sa.Column("implementation_id", sa.String(64), nullable=True)),
        ("test_execution_id", sa.Column("test_execution_id", sa.String(64), nullable=True)),
        ("controlled_retest_id", sa.Column("controlled_retest_id", sa.String(64), nullable=True)),
        ("workflow_status", sa.Column("workflow_status", sa.String(64), nullable=False, server_default="current")),
        ("invalidation_reason", sa.Column("invalidation_reason", sa.Text(), nullable=True)),
    ):
        if name not in fix_columns:
            op.add_column("fix_verifications", column)
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_fix_verification_controlled_retest "
        "ON fix_verifications (controlled_retest_id) WHERE controlled_retest_id IS NOT NULL"
    ))

    outcome_columns = {column["name"] for column in inspector.get_columns("verification_outcomes")}
    if "implementation_id" not in outcome_columns:
        op.add_column("verification_outcomes", sa.Column("implementation_id", sa.String(64), nullable=True))
    if "controlled_retest_id" not in outcome_columns:
        op.add_column("verification_outcomes", sa.Column("controlled_retest_id", sa.String(64), nullable=True))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_outcome_controlled_retest "
        "ON verification_outcomes (controlled_retest_id) WHERE controlled_retest_id IS NOT NULL"
    ))

    op.execute(sa.text(
        """
        WITH ranked AS (
          SELECT id, row_number() OVER (
            PARTITION BY remediation_type ORDER BY created_at, id
          ) AS ordinal
          FROM remediation_playbooks WHERE active IS TRUE
        )
        UPDATE remediation_playbooks p SET active = false
        FROM ranked r WHERE p.id = r.id AND r.ordinal > 1
        """
    ))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_remediation_playbooks_active_type "
        "ON remediation_playbooks (remediation_type) WHERE active IS TRUE"
    ))

    for table, name, columns, target, remote in (
        ("fix_verifications", "fk_fix_rca_028", ["root_cause_analysis_id"], "root_cause_analyses", ["analysis_id"]),
        ("fix_verifications", "fk_fix_review_028", ["review_decision_id"], "review_decisions", ["id"]),
        ("fix_verifications", "fk_fix_diagnosis_028", ["remediation_diagnosis_id"], "remediation_diagnoses", ["diagnosis_id"]),
        ("fix_verifications", "fk_fix_action_028", ["remediation_action_id"], "remediation_actions", ["remediation_action_id"]),
        ("fix_verifications", "fk_fix_implementation_028", ["implementation_id"], "remediation_implementation_records", ["implementation_id"]),
        ("fix_verifications", "fk_fix_test_028", ["test_execution_id"], "remediation_test_executions", ["execution_id"]),
        ("fix_verifications", "fk_fix_retest_028", ["controlled_retest_id"], "controlled_retests", ["controlled_retest_id"]),
        ("verification_outcomes", "fk_outcome_implementation_028", ["implementation_id"], "remediation_implementation_records", ["implementation_id"]),
        ("verification_outcomes", "fk_outcome_retest_028", ["controlled_retest_id"], "controlled_retests", ["controlled_retest_id"]),
    ):
        op.create_foreign_key(name, table, target, columns, remote, ondelete="RESTRICT")


def downgrade() -> None:
    pass
