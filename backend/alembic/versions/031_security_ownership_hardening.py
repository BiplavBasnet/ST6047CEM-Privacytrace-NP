"""Security ownership and controlled-retest completeness hardening.

Revision ID: 031_security_ownership_hardening
Revises: 030_exact_report_provenance
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "031_security_ownership_hardening"
down_revision: Union[str, None] = "030_exact_report_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Every referenced tuple below has an exact unique target here. Global public IDs
# are already unique; these pair indexes let PostgreSQL enforce incident ownership.
UNIQUE_INDEXES = (
    ("uq031_rca_id_incident", "root_cause_analyses", ("analysis_id", "incident_id")),
    (
        "uq031_rca_report_anchor",
        "root_cause_analyses",
        ("analysis_id", "incident_id", "analysis_version", "evidence_snapshot_hash"),
    ),
    ("uq031_review_id_incident", "review_decisions", ("id", "incident_id")),
    ("uq031_diagnosis_id_incident", "remediation_diagnoses", ("diagnosis_id", "incident_id")),
    ("uq031_action_id_incident", "remediation_actions", ("remediation_action_id", "incident_id")),
    ("uq031_patch_id_incident", "patch_proposals", ("patch_proposal_id", "incident_id")),
    (
        "uq031_implementation_id_incident",
        "remediation_implementation_records",
        ("implementation_id", "incident_id"),
    ),
    ("uq031_test_id_incident", "remediation_test_executions", ("execution_id", "incident_id")),
    ("uq031_retest_id_incident", "controlled_retests", ("controlled_retest_id", "incident_id")),
    ("uq031_fix_id_incident", "fix_verifications", ("id", "incident_id")),
    (
        "uq031_outcome_id_incident",
        "verification_outcomes",
        ("verification_outcome_id", "incident_id"),
    ),
)


def _fk(name, child, local_id, parent, remote_id):
    return (name, child, (local_id, "incident_id"), parent, (remote_id, "incident_id"))


COMPOSITE_FKS = (
    _fk("fk031_review_rca_incident", "review_decisions", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_diagnosis_rca_incident", "remediation_diagnoses", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_diagnosis_review_incident", "remediation_diagnoses", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_action_rca_incident", "remediation_actions", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_action_review_incident", "remediation_actions", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_action_diagnosis_incident", "remediation_actions", "diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_patch_rca_incident", "patch_proposals", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_patch_diagnosis_incident", "patch_proposals", "diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_patch_action_incident", "patch_proposals", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_impl_rca_incident", "remediation_implementation_records", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_impl_review_incident", "remediation_implementation_records", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_impl_diagnosis_incident", "remediation_implementation_records", "diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_impl_action_incident", "remediation_implementation_records", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_impl_patch_incident", "remediation_implementation_records", "patch_proposal_id", "patch_proposals", "patch_proposal_id"),
    _fk("fk031_test_action_incident", "remediation_test_executions", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_test_impl_incident", "remediation_test_executions", "implementation_id", "remediation_implementation_records", "implementation_id"),
    _fk("fk031_test_patch_incident", "remediation_test_executions", "patch_proposal_id", "patch_proposals", "patch_proposal_id"),
    _fk("fk031_retest_rca_incident", "controlled_retests", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_retest_review_incident", "controlled_retests", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_retest_diagnosis_incident", "controlled_retests", "diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_retest_action_incident", "controlled_retests", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_retest_impl_incident", "controlled_retests", "implementation_id", "remediation_implementation_records", "implementation_id"),
    _fk("fk031_retest_test_incident", "controlled_retests", "test_execution_id", "remediation_test_executions", "execution_id"),
    _fk("fk031_fix_rca_incident", "fix_verifications", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_fix_review_incident", "fix_verifications", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_fix_diagnosis_incident", "fix_verifications", "remediation_diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_fix_action_incident", "fix_verifications", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_fix_impl_incident", "fix_verifications", "implementation_id", "remediation_implementation_records", "implementation_id"),
    _fk("fk031_fix_test_incident", "fix_verifications", "test_execution_id", "remediation_test_executions", "execution_id"),
    _fk("fk031_fix_retest_incident", "fix_verifications", "controlled_retest_id", "controlled_retests", "controlled_retest_id"),
    _fk("fk031_outcome_rca_incident", "verification_outcomes", "root_cause_analysis_id", "root_cause_analyses", "analysis_id"),
    _fk("fk031_outcome_review_incident", "verification_outcomes", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_outcome_diagnosis_incident", "verification_outcomes", "remediation_diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_outcome_action_incident", "verification_outcomes", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_outcome_patch_incident", "verification_outcomes", "patch_proposal_id", "patch_proposals", "patch_proposal_id"),
    _fk("fk031_outcome_impl_incident", "verification_outcomes", "implementation_id", "remediation_implementation_records", "implementation_id"),
    _fk("fk031_outcome_test_incident", "verification_outcomes", "test_execution_id", "remediation_test_executions", "execution_id"),
    _fk("fk031_outcome_retest_incident", "verification_outcomes", "controlled_retest_id", "controlled_retests", "controlled_retest_id"),
    _fk("fk031_outcome_fix_incident", "verification_outcomes", "fix_verification_id", "fix_verifications", "id"),
    _fk("fk031_report_review_incident", "reports", "review_decision_id", "review_decisions", "id"),
    _fk("fk031_report_diagnosis_incident", "reports", "remediation_diagnosis_id", "remediation_diagnoses", "diagnosis_id"),
    _fk("fk031_report_action_incident", "reports", "remediation_action_id", "remediation_actions", "remediation_action_id"),
    _fk("fk031_report_patch_incident", "reports", "patch_proposal_id", "patch_proposals", "patch_proposal_id"),
    _fk("fk031_report_impl_incident", "reports", "implementation_id", "remediation_implementation_records", "implementation_id"),
    _fk("fk031_report_test_incident", "reports", "test_execution_id", "remediation_test_executions", "execution_id"),
    _fk("fk031_report_retest_incident", "reports", "controlled_retest_id", "controlled_retests", "controlled_retest_id"),
    _fk("fk031_report_fix_incident", "reports", "fix_verification_id", "fix_verifications", "id"),
    _fk("fk031_report_outcome_incident", "reports", "verification_outcome_id", "verification_outcomes", "verification_outcome_id"),
    (
        "fk031_report_rca_anchor",
        "reports",
        ("root_cause_analysis_id", "incident_id", "root_cause_analysis_version", "evidence_snapshot_hash"),
        "root_cause_analyses",
        ("analysis_id", "incident_id", "analysis_version", "evidence_snapshot_hash"),
    ),
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("Migration 031 requires PostgreSQL.")
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("controlled_retests")}
    if "required_dimensions" not in columns:
        op.add_column("controlled_retests", sa.Column("required_dimensions", postgresql.JSONB(), nullable=False, server_default="[]"))
    if "missing_dimensions" not in columns:
        op.add_column("controlled_retests", sa.Column("missing_dimensions", postgresql.JSONB(), nullable=False, server_default="[]"))
    op.execute("UPDATE controlled_retests SET dimensions_match=false, status='inconclusive', raw_exposure_after_change=NULL, missing_dimensions='[\"legacy_dimension_contract\"]'::jsonb WHERE required_dimensions='[]'::jsonb")

    for name, table, columns in UNIQUE_INDEXES:
        op.create_index(name, table, list(columns), unique=True)
    for name, child, local, parent, remote in COMPOSITE_FKS:
        op.execute(
            f"ALTER TABLE {child} ADD CONSTRAINT {name} FOREIGN KEY ({', '.join(local)}) "
            f"REFERENCES {parent} ({', '.join(remote)}) ON DELETE RESTRICT NOT VALID"
        )

    inspector = sa.inspect(bind)
    for fk in inspector.get_foreign_keys("reports"):
        if fk.get("referred_table") == "incidents":
            op.drop_constraint(fk["name"], "reports", type_="foreignkey")
    op.create_foreign_key("fk_reports_incident_restrict", "reports", "incidents", ["incident_id"], ["incident_id"], ondelete="RESTRICT")


def downgrade() -> None:
    op.drop_constraint("fk_reports_incident_restrict", "reports", type_="foreignkey")
    for name, child, *_ in reversed(COMPOSITE_FKS):
        op.drop_constraint(name, child, type_="foreignkey")
    for name, table, _ in reversed(UNIQUE_INDEXES):
        op.drop_index(name, table_name=table)
    op.create_foreign_key("fk_reports_incident", "reports", "incidents", ["incident_id"], ["incident_id"], ondelete="CASCADE")
    op.drop_column("controlled_retests", "missing_dimensions")
    op.drop_column("controlled_retests", "required_dimensions")
