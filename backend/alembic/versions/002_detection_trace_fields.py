"""detection trace fields

Revision ID: 002_detection_trace
Revises: 001_initial
Create Date: 2026-05-15

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_detection_trace"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {c["name"] for c in inspector.get_columns("detections")}

    if "normalized_event_id" not in columns:
        op.add_column(
            "detections",
            sa.Column("normalized_event_id", sa.String(length=64), nullable=True),
        )
    if "raw_value_hash" not in columns:
        op.add_column(
            "detections",
            sa.Column("raw_value_hash", sa.String(length=128), nullable=True),
        )

    fk_names = {fk["name"] for fk in inspector.get_foreign_keys("detections")}
    if "fk_detections_normalized_event_id" not in fk_names:
        op.create_foreign_key(
            "fk_detections_normalized_event_id",
            "detections",
            "normalized_events",
            ["normalized_event_id"],
            ["event_id"],
            ondelete="SET NULL",
        )

    index_names = {idx["name"] for idx in inspector.get_indexes("detections")}
    if "ix_detections_normalized_event_id" not in index_names:
        op.create_index(
            "ix_detections_normalized_event_id",
            "detections",
            ["normalized_event_id"],
        )


def downgrade() -> None:
    op.drop_index("ix_detections_normalized_event_id", table_name="detections")
    op.drop_constraint("fk_detections_normalized_event_id", "detections", type_="foreignkey")
    op.drop_column("detections", "raw_value_hash")
    op.drop_column("detections", "normalized_event_id")
