"""root cause spec fields

Revision ID: 003_root_cause_spec
Revises: 002_detection_trace
Create Date: 2026-05-15

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_root_cause_spec"
down_revision: Union[str, None] = "002_detection_trace"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {c["name"] for c in inspector.get_columns("root_cause_scores")}

    if "root_cause_id" not in columns:
        op.add_column(
            "root_cause_scores",
            sa.Column("root_cause_id", sa.String(length=64), nullable=True),
        )
        op.execute(
            "UPDATE root_cause_scores SET root_cause_id = 'RCA-LEGACY-' || id::text "
            "WHERE root_cause_id IS NULL"
        )
        op.alter_column("root_cause_scores", "root_cause_id", nullable=False)
        op.create_index("ix_root_cause_scores_root_cause_id", "root_cause_scores", ["root_cause_id"])
        op.create_unique_constraint(
            "uq_root_cause_scores_root_cause_id",
            "root_cause_scores",
            ["root_cause_id"],
        )

    if "likely_root_cause" not in columns:
        op.add_column(
            "root_cause_scores",
            sa.Column("likely_root_cause", sa.String(length=255), nullable=True),
        )
        op.execute(
            "UPDATE root_cause_scores SET likely_root_cause = cause_name "
            "WHERE likely_root_cause IS NULL"
        )
        op.alter_column("root_cause_scores", "likely_root_cause", nullable=False)

    if "confidence_band" not in columns:
        op.add_column(
            "root_cause_scores",
            sa.Column("confidence_band", sa.String(length=32), nullable=True),
        )

    if "recommended_fix" not in columns:
        op.add_column(
            "root_cause_scores",
            sa.Column("recommended_fix", sa.Text(), nullable=True),
        )

    if "human_review_required" not in columns:
        op.add_column(
            "root_cause_scores",
            sa.Column(
                "human_review_required",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
            ),
        )

    if "created_at" not in columns:
        op.add_column(
            "root_cause_scores",
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )


def downgrade() -> None:
    op.drop_column("root_cause_scores", "created_at")
    op.drop_column("root_cause_scores", "human_review_required")
    op.drop_column("root_cause_scores", "recommended_fix")
    op.drop_column("root_cause_scores", "confidence_band")
    op.drop_column("root_cause_scores", "likely_root_cause")
    op.drop_constraint("uq_root_cause_scores_root_cause_id", "root_cause_scores", type_="unique")
    op.drop_index("ix_root_cause_scores_root_cause_id", table_name="root_cause_scores")
    op.drop_column("root_cause_scores", "root_cause_id")
