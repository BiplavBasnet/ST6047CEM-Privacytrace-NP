"""Persist exact final-report lifecycle provenance.

Revision ID: 030_exact_report_provenance
Revises: 029_alert_correlation_integrity
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "030_exact_report_provenance"
down_revision: Union[str, None] = "029_alert_correlation_integrity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("Migration 030 requires PostgreSQL.")
    inspector = sa.inspect(bind)
    if "reports" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("reports")}
    for name, column in (
        ("root_cause_analysis_version", sa.Column("root_cause_analysis_version", sa.Integer(), nullable=True)),
        ("implementation_id", sa.Column("implementation_id", sa.String(64), nullable=True)),
        ("controlled_retest_id", sa.Column("controlled_retest_id", sa.String(64), nullable=True)),
        ("fix_verification_id", sa.Column("fix_verification_id", sa.Integer(), nullable=True)),
        ("taxonomy_version", sa.Column("taxonomy_version", sa.String(64), nullable=True)),
        ("exposure_policy_version", sa.Column("exposure_policy_version", sa.String(64), nullable=True)),
        ("workflow_chain_status", sa.Column("workflow_chain_status", sa.String(32), nullable=False, server_default="blocked")),
    ):
        if name not in columns:
            op.add_column("reports", column)

    existing_fks = {fk.get("name") for fk in sa.inspect(bind).get_foreign_keys("reports")}
    for name, local, remote in (
        ("fk_reports_root_cause_analysis", "root_cause_analysis_id", "root_cause_analyses(analysis_id)"),
        ("fk_reports_review_decision", "review_decision_id", "review_decisions(id)"),
        ("fk_reports_diagnosis", "remediation_diagnosis_id", "remediation_diagnoses(diagnosis_id)"),
        ("fk_reports_action", "remediation_action_id", "remediation_actions(remediation_action_id)"),
        ("fk_reports_implementation", "implementation_id", "remediation_implementation_records(implementation_id)"),
        ("fk_reports_patch", "patch_proposal_id", "patch_proposals(patch_proposal_id)"),
        ("fk_reports_test_execution", "test_execution_id", "remediation_test_executions(execution_id)"),
        ("fk_reports_controlled_retest", "controlled_retest_id", "controlled_retests(controlled_retest_id)"),
        ("fk_reports_fix_verification", "fix_verification_id", "fix_verifications(id)"),
        ("fk_reports_verification_outcome", "verification_outcome_id", "verification_outcomes(verification_outcome_id)"),
    ):
        if name not in existing_fks:
            op.execute(
                f"ALTER TABLE reports ADD CONSTRAINT {name} FOREIGN KEY ({local}) "
                f"REFERENCES {remote} ON DELETE RESTRICT NOT VALID"
            )


def downgrade() -> None:
    bind = op.get_bind()
    if "reports" not in sa.inspect(bind).get_table_names():
        return
    for name in (
        "fk_reports_verification_outcome", "fk_reports_fix_verification",
        "fk_reports_controlled_retest", "fk_reports_test_execution", "fk_reports_patch",
        "fk_reports_implementation", "fk_reports_action", "fk_reports_diagnosis",
        "fk_reports_review_decision", "fk_reports_root_cause_analysis",
    ):
        op.execute(f"ALTER TABLE reports DROP CONSTRAINT IF EXISTS {name}")
    existing = {column["name"] for column in sa.inspect(bind).get_columns("reports")}
    for column in (
        "workflow_chain_status", "exposure_policy_version", "taxonomy_version",
        "fix_verification_id", "controlled_retest_id", "implementation_id",
        "root_cause_analysis_version",
    ):
        if column in existing:
            op.drop_column("reports", column)
