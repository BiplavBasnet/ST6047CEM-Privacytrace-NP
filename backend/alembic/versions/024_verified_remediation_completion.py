"""Durable verified remediation learning + controlled patch proposals.

Revision ID: 024_verified_remediation_completion
Revises: 023_problem_specific_remediation
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "024_verified_remediation_completion"
down_revision: Union[str, None] = "023_problem_specific_remediation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "patch_proposals" not in tables:
        op.create_table(
            "patch_proposals",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("patch_proposal_id", sa.String(length=64), nullable=False),
            sa.Column("remediation_action_id", sa.String(length=64), nullable=True),
            sa.Column("diagnosis_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("repository_reference_safe", sa.String(length=512), nullable=True),
            sa.Column("base_commit", sa.String(length=128), nullable=True),
            sa.Column("temporary_workspace", sa.String(length=1024), nullable=False),
            sa.Column("temporary_branch", sa.String(length=255), nullable=True),
            sa.Column("affected_files", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("patch_hash", sa.String(length=128), nullable=False),
            sa.Column("safe_diff", sa.Text(), nullable=False),
            sa.Column("safety_result", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("human_approval_status", sa.String(length=64), nullable=True),
            sa.Column("approved_by", sa.Integer(), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rollback_status", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("patch_proposal_id"),
        )
        op.create_index("ix_patch_proposals_patch_proposal_id", "patch_proposals", ["patch_proposal_id"])
        op.create_index("ix_patch_proposals_incident_id", "patch_proposals", ["incident_id"])
        op.create_index("ix_patch_proposals_status", "patch_proposals", ["status"])

    if "verified_remediation_cases" not in tables:
        op.create_table(
            "verified_remediation_cases",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("verified_case_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("diagnosis_id", sa.String(length=64), nullable=True),
            sa.Column("remediation_action_id", sa.String(length=64), nullable=True),
            sa.Column("patch_proposal_id", sa.String(length=64), nullable=True),
            sa.Column("sensitive_type", sa.String(length=128), nullable=True),
            sa.Column("exposure_location", sa.String(length=128), nullable=True),
            sa.Column("root_cause_category", sa.String(length=128), nullable=True),
            sa.Column("affected_component", sa.String(length=255), nullable=True),
            sa.Column("remediation_type", sa.String(length=128), nullable=True),
            sa.Column("approved_remediation_summary", sa.Text(), nullable=True),
            sa.Column("implementation_mode", sa.String(length=64), nullable=True),
            sa.Column("tests_passed", sa.Boolean(), nullable=True),
            sa.Column("verification_result", sa.String(length=64), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("verified_by", sa.String(length=255), nullable=True),
            sa.Column("eligible_for_learning", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("eligibility_reason", sa.Text(), nullable=True),
            sa.Column("policy_version", sa.String(length=64), nullable=False, server_default="playbook-v1"),
            sa.Column("limitations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("verified_case_id"),
        )
        op.create_index("ix_verified_remediation_cases_verified_case_id", "verified_remediation_cases", ["verified_case_id"])
        op.create_index("ix_verified_remediation_cases_incident_id", "verified_remediation_cases", ["incident_id"])

    if "remediation_playbooks" not in tables:
        op.create_table(
            "remediation_playbooks",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("playbook_id", sa.String(length=64), nullable=False),
            sa.Column("root_cause_category", sa.String(length=128), nullable=False),
            sa.Column("exposure_locations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("sensitive_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("component_category", sa.String(length=255), nullable=True),
            sa.Column("remediation_pattern", sa.String(length=128), nullable=False),
            sa.Column("remediation_type", sa.String(length=128), nullable=False),
            sa.Column("test_pattern", sa.Text(), nullable=True),
            sa.Column("retest_pattern", sa.Text(), nullable=True),
            sa.Column("rollback_guidance", sa.Text(), nullable=True),
            sa.Column("verified_success_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("verified_failure_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("inconclusive_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("version", sa.String(length=64), nullable=False, server_default="1"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("playbook_id"),
        )
        op.create_index("ix_remediation_playbooks_playbook_id", "remediation_playbooks", ["playbook_id"])
        op.create_index("ix_remediation_playbooks_remediation_type", "remediation_playbooks", ["remediation_type"])

    # Provenance columns on remediation_diagnoses (additive).
    if "remediation_diagnoses" in tables:
        cols = {c["name"] for c in inspector.get_columns("remediation_diagnoses")}
        if "original_ai_payload" not in cols:
            op.add_column(
                "remediation_diagnoses",
                sa.Column("original_ai_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            )
        if "approved_payload" not in cols:
            op.add_column(
                "remediation_diagnoses",
                sa.Column("approved_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            )
        if "edited_fields" not in cols:
            op.add_column(
                "remediation_diagnoses",
                sa.Column("edited_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            )


def downgrade() -> None:
    op.drop_table("remediation_playbooks")
    op.drop_table("verified_remediation_cases")
    op.drop_table("patch_proposals")
