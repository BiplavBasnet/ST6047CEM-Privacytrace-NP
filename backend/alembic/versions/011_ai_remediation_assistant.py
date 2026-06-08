"""AI Remediation Assistant suggestions

Revision ID: 011_ai_remediation_assistant
Revises: 010_live_privacy_monitor
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "011_ai_remediation_assistant"
down_revision: Union[str, None] = "010_live_privacy_monitor"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ai_remediation_suggestions" in inspector.get_table_names():
        return

    op.create_table(
        "ai_remediation_suggestions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("suggestion_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ai_provider", sa.String(length=128), nullable=True),
        sa.Column("ai_model", sa.String(length=255), nullable=True),
        sa.Column("input_safety_status", sa.String(length=64), nullable=False),
        sa.Column("output_safety_status", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("masked_input_summary_hash", sa.String(length=128), nullable=False),
        sa.Column("suggestion_summary", sa.Text(), nullable=True),
        sa.Column("likely_issue_area", sa.String(length=255), nullable=True),
        sa.Column("remediation_actions", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("code_or_config_areas", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("suggested_tests", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("retest_evidence_required", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("limitations", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("human_review_required", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("reviewer_decision", sa.String(length=64), nullable=True),
        sa.Column("reviewer_notes", sa.Text(), nullable=True),
        sa.Column("accepted_as_remediation_action_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("suggestion_id"),
    )
    op.create_index("ix_ai_remediation_suggestions_suggestion_id", "ai_remediation_suggestions", ["suggestion_id"], unique=False)
    op.create_index("ix_ai_remediation_suggestions_incident_id", "ai_remediation_suggestions", ["incident_id"], unique=False)
    op.create_index("ix_ai_remediation_suggestions_requested_by_user_id", "ai_remediation_suggestions", ["requested_by_user_id"], unique=False)
    op.create_index("ix_ai_remediation_suggestions_status", "ai_remediation_suggestions", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_ai_remediation_suggestions_status", table_name="ai_remediation_suggestions")
    op.drop_index("ix_ai_remediation_suggestions_requested_by_user_id", table_name="ai_remediation_suggestions")
    op.drop_index("ix_ai_remediation_suggestions_incident_id", table_name="ai_remediation_suggestions")
    op.drop_index("ix_ai_remediation_suggestions_suggestion_id", table_name="ai_remediation_suggestions")
    op.drop_table("ai_remediation_suggestions")
