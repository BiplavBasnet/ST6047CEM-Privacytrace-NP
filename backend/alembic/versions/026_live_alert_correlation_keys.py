"""Add correlation_keys JSONB on privacy_alerts for live ingest provenance.

Revision ID: 026_live_alert_correlation_keys
Revises: 025_workflow_provenance_hardening
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "026_live_alert_correlation_keys"
down_revision: Union[str, None] = "025_workflow_provenance_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "privacy_alerts" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("privacy_alerts")}
    if "correlation_keys" not in cols:
        op.add_column(
            "privacy_alerts",
            sa.Column("correlation_keys", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "privacy_alerts" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("privacy_alerts")}
    if "correlation_keys" in cols:
        op.drop_column("privacy_alerts", "correlation_keys")
