"""Phase 12.2 traceability hardening fields

Revision ID: 009_phase12_2_traceability
Revises: 008_phase11_85_scanner_bridge
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "009_phase12_2_traceability"
down_revision: Union[str, None] = "008_phase11_85_scanner_bridge"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {c["name"] for c in inspector.get_columns("root_cause_scores")}

    columns = [
        "score_breakdown",
        "matched_signals",
        "negative_signals",
        "correlation_reasons",
        "contradicting_evidence",
        "evidence_roles",
        "suggested_actions",
    ]
    for column_name in columns:
        if column_name in existing:
            continue
        op.add_column(
            "root_cause_scores",
            sa.Column(
                column_name,
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )


def downgrade() -> None:
    op.drop_column("root_cause_scores", "suggested_actions")
    op.drop_column("root_cause_scores", "evidence_roles")
    op.drop_column("root_cause_scores", "contradicting_evidence")
    op.drop_column("root_cause_scores", "correlation_reasons")
    op.drop_column("root_cause_scores", "negative_signals")
    op.drop_column("root_cause_scores", "matched_signals")
    op.drop_column("root_cause_scores", "score_breakdown")
