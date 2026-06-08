"""Live Privacy Monitor privacy alerts

Revision ID: 010_live_privacy_monitor
Revises: 009_phase12_2_traceability
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "010_live_privacy_monitor"
down_revision: Union[str, None] = "009_phase12_2_traceability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "privacy_alerts" in inspector.get_table_names():
        return

    op.create_table(
        "privacy_alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("alert_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source_type", sa.String(length=128), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=True),
        sa.Column("source_format", sa.String(length=64), nullable=False),
        sa.Column("service_name", sa.String(length=255), nullable=True),
        sa.Column("endpoint", sa.String(length=512), nullable=True),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.Enum("low", "medium", "high", "critical", name="privacy_alert_severity", native_enum=False), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("sensitive_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("masked_values", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("detection_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("evidence_id", sa.String(length=64), nullable=True),
        sa.Column("linked_incident_id", sa.String(length=64), nullable=True),
        sa.Column("raw_event_hash", sa.String(length=128), nullable=False),
        sa.Column("safety_status", sa.String(length=32), nullable=False),
        sa.Column("alert_summary", sa.Text(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_files.evidence_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["linked_incident_id"], ["incidents.incident_id"], ondelete="SET NULL"),
        sa.UniqueConstraint("alert_id"),
    )
    op.create_index("ix_privacy_alerts_alert_id", "privacy_alerts", ["alert_id"], unique=False)
    op.create_index("ix_privacy_alerts_evidence_id", "privacy_alerts", ["evidence_id"], unique=False)
    op.create_index("ix_privacy_alerts_linked_incident_id", "privacy_alerts", ["linked_incident_id"], unique=False)
    op.create_index("ix_privacy_alerts_status", "privacy_alerts", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_privacy_alerts_status", table_name="privacy_alerts")
    op.drop_index("ix_privacy_alerts_linked_incident_id", table_name="privacy_alerts")
    op.drop_index("ix_privacy_alerts_evidence_id", table_name="privacy_alerts")
    op.drop_index("ix_privacy_alerts_alert_id", table_name="privacy_alerts")
    op.drop_table("privacy_alerts")
