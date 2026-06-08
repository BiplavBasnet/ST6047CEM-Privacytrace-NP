"""Alembic revision 037 — connector ingest idempotency key.

Revision ID: 037_connector_client_event_id
Revises: 036_controlled_rollback_learning
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "037_connector_client_event_id"
down_revision: Union[str, None] = "036_controlled_rollback_learning"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def _indexes(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {idx["name"] for idx in inspector.get_indexes(table)}


def upgrade() -> None:
    if "client_event_id" not in _columns("integration_events"):
        op.add_column(
            "integration_events",
            sa.Column("client_event_id", sa.String(length=255), nullable=True),
        )
    if "uq_integration_events_source_client_event" not in _indexes("integration_events"):
        op.create_index(
            "uq_integration_events_source_client_event",
            "integration_events",
            ["source_name", "client_event_id"],
            unique=True,
            postgresql_where=sa.text(
                "client_event_id IS NOT NULL AND source_name IS NOT NULL"
            ),
        )


def downgrade() -> None:
    if "uq_integration_events_source_client_event" in _indexes("integration_events"):
        op.drop_index(
            "uq_integration_events_source_client_event",
            table_name="integration_events",
        )
    if "client_event_id" in _columns("integration_events"):
        op.drop_column("integration_events", "client_event_id")
