"""llm reports table

Revision ID: 004_llm_reports
Revises: 003_root_cause_spec
Create Date: 2026-05-15

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004_llm_reports"
down_revision: Union[str, None] = "003_root_cause_spec"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "llm_reports" in inspector.get_table_names():
        return

    op.create_table(
        "llm_reports",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("provider_used", sa.String(length=32), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=True),
        sa.Column("input_context_hash", sa.String(length=128), nullable=False),
        sa.Column("output_json", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("safety_status", sa.String(length=32), nullable=False),
        sa.Column("validation_errors", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id", name="uq_llm_reports_report_id"),
    )
    op.create_index("ix_llm_reports_incident_id", "llm_reports", ["incident_id"])
    op.create_index("ix_llm_reports_report_id", "llm_reports", ["report_id"])


def downgrade() -> None:
    op.drop_index("ix_llm_reports_report_id", table_name="llm_reports")
    op.drop_index("ix_llm_reports_incident_id", table_name="llm_reports")
    op.drop_table("llm_reports")
