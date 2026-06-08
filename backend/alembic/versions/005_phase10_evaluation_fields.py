"""Phase 10 evaluation metric metadata fields

Revision ID: 005_phase10_evaluation
Revises: 004_llm_reports
Create Date: 2026-05-15

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "005_phase10_evaluation"
down_revision: Union[str, None] = "004_llm_reports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COLUMNS = (
    ("thesis_claim", sa.Text()),
    ("baseline_name", sa.String(length=128)),
    ("calculation_method", sa.Text()),
    ("evidence_source", sa.Text()),
)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "evaluation_metrics" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("evaluation_metrics")}
    for name, col_type in _NEW_COLUMNS:
        if name not in existing:
            op.add_column("evaluation_metrics", sa.Column(name, col_type, nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "evaluation_metrics" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("evaluation_metrics")}
    for name, _ in reversed(_NEW_COLUMNS):
        if name in existing:
            op.drop_column("evaluation_metrics", name)
