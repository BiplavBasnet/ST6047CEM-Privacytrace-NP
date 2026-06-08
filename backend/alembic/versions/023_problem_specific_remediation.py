"""Evidence-grounded problem-specific remediation diagnoses + learning helpers.

Revision ID: 023_problem_specific_remediation
Revises: 022_root_cause_versioning

Creates remediation_diagnoses (guarded). Safe for from-scratch 001 create_all
because the table is listed in env.py _POST_INITIAL_TABLES.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "023_problem_specific_remediation"
down_revision: Union[str, None] = "022_root_cause_versioning"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "remediation_diagnoses" not in tables:
        op.create_table(
            "remediation_diagnoses",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("diagnosis_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("root_cause_analysis_id", sa.String(length=64), nullable=True),
            sa.Column("evidence_snapshot_hash", sa.String(length=128), nullable=False),
            sa.Column("model_provider", sa.String(length=128), nullable=True),
            sa.Column("model_name", sa.String(length=255), nullable=True),
            sa.Column("prompt_template_version", sa.String(length=64), nullable=True),
            sa.Column("recommendation_policy_version", sa.String(length=64), nullable=True),
            sa.Column("problem_statement", sa.Text(), nullable=False),
            sa.Column("technical_mechanism", sa.Text(), nullable=False),
            sa.Column("affected_service", sa.String(length=255), nullable=True),
            sa.Column("affected_endpoint", sa.String(length=512), nullable=True),
            sa.Column("affected_component", sa.String(length=255), nullable=True),
            sa.Column("affected_file", sa.String(length=1024), nullable=True),
            sa.Column("affected_function", sa.String(length=255), nullable=True),
            sa.Column("affected_configuration", sa.String(length=255), nullable=True),
            sa.Column(
                "exact_source_location_known",
                sa.Boolean(),
                server_default="false",
                nullable=False,
            ),
            sa.Column(
                "supporting_evidence_ids",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
            ),
            sa.Column(
                "contradicting_evidence_ids",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
            ),
            sa.Column(
                "missing_evidence",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
            ),
            sa.Column("diagnosis_confidence", sa.String(length=64), nullable=False),
            sa.Column("limitations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column(
                "primary_remediation",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
            ),
            sa.Column(
                "alternative_remediations",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
            ),
            sa.Column(
                "exact_change_available",
                sa.Boolean(),
                server_default="false",
                nullable=False,
            ),
            sa.Column("proposed_change", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column("status", sa.String(length=64), nullable=False),
            sa.Column("reviewer_decision", sa.String(length=64), nullable=True),
            sa.Column("reviewer_notes", sa.Text(), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("reviewed_by_user_id", sa.Integer(), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(
                ["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(["reviewed_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("diagnosis_id"),
        )
        op.create_index(
            "ix_remediation_diagnoses_diagnosis_id",
            "remediation_diagnoses",
            ["diagnosis_id"],
        )
        op.create_index(
            "ix_remediation_diagnoses_incident_id",
            "remediation_diagnoses",
            ["incident_id"],
        )
        op.create_index(
            "ix_remediation_diagnoses_status",
            "remediation_diagnoses",
            ["status"],
        )


def downgrade() -> None:
    op.drop_index("ix_remediation_diagnoses_status", table_name="remediation_diagnoses")
    op.drop_index("ix_remediation_diagnoses_incident_id", table_name="remediation_diagnoses")
    op.drop_index("ix_remediation_diagnoses_diagnosis_id", table_name="remediation_diagnoses")
    op.drop_table("remediation_diagnoses")
