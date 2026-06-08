"""Universal Integration Gateway tokens and alert correlation metadata.

Revision ID: 012_universal_integration_gw
Revises: 011_ai_remediation_assistant
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "012_universal_integration_gw"
down_revision: Union[str, None] = "011_ai_remediation_assistant"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "integration_tokens" not in tables:
        op.create_table(
            "integration_tokens",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("token_id", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("source_name", sa.String(length=255), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("token_prefix", sa.String(length=20), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("token_id"),
            sa.UniqueConstraint("token_hash"),
        )
        op.create_index("ix_integration_tokens_token_id", "integration_tokens", ["token_id"])
        op.create_index("ix_integration_tokens_token_hash", "integration_tokens", ["token_hash"])
        op.create_index("ix_integration_tokens_created_by_user_id", "integration_tokens", ["created_by_user_id"])
        op.create_index("ix_integration_tokens_is_active", "integration_tokens", ["is_active"])

    alert_columns = {column["name"] for column in inspector.get_columns("privacy_alerts")}
    if "ingestion_source" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column("ingestion_source", sa.String(length=64), server_default="live_monitor", nullable=False),
        )
    if "missing_metadata" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column("missing_metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        )
    if "correlation_recommendations" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column("correlation_recommendations", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        )
    if "evidence_strength" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column("evidence_strength", sa.String(length=32), server_default="limited", nullable=False),
        )


def downgrade() -> None:
    op.drop_column("privacy_alerts", "evidence_strength")
    op.drop_column("privacy_alerts", "correlation_recommendations")
    op.drop_column("privacy_alerts", "missing_metadata")
    op.drop_column("privacy_alerts", "ingestion_source")
    op.drop_index("ix_integration_tokens_is_active", table_name="integration_tokens")
    op.drop_index("ix_integration_tokens_created_by_user_id", table_name="integration_tokens")
    op.drop_index("ix_integration_tokens_token_hash", table_name="integration_tokens")
    op.drop_index("ix_integration_tokens_token_id", table_name="integration_tokens")
    op.drop_table("integration_tokens")
