"""Alembic revision 036 — rollback ledger + remediation fingerprint.

Revision ID: 036_controlled_rollback_learning
Revises: 035_onboarding_hardening
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "036_controlled_rollback_learning"
down_revision: Union[str, None] = "035_onboarding_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    tables = _tables()
    if "rollback_executions" not in tables:
        op.create_table(
            "rollback_executions",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("rollback_execution_id", sa.String(length=64), nullable=False),
            sa.Column("incident_id", sa.String(), nullable=False),
            sa.Column("implementation_id", sa.String(length=64), nullable=True),
            sa.Column("patch_proposal_id", sa.String(length=64), nullable=False),
            sa.Column("baseline_snapshot_ref", sa.String(length=128), nullable=False),
            sa.Column("expected_hashes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("restored_hashes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("trigger", sa.String(length=64), nullable=False),
            sa.Column("trigger_reference", sa.String(length=128), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("performed_mode", sa.String(length=32), nullable=False),
            sa.Column("rollback_verified", sa.Boolean(), nullable=True),
            sa.Column("verification_result", sa.String(length=32), nullable=True),
            sa.Column("failure_reason_safe", sa.Text(), nullable=True),
            sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("actor_label", sa.String(length=128), nullable=False, server_default="system"),
            sa.Column("generation", sa.String(length=32), nullable=False, server_default="v1"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(
                ["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"
            ),
            sa.ForeignKeyConstraint(
                ["implementation_id"],
                ["remediation_implementation_records.implementation_id"],
                ondelete="RESTRICT",
            ),
            sa.ForeignKeyConstraint(
                ["patch_proposal_id"],
                ["patch_proposals.patch_proposal_id"],
                ondelete="RESTRICT",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("rollback_execution_id"),
            sa.UniqueConstraint(
                "implementation_id",
                "trigger",
                "trigger_reference",
                name="uq_rollback_executions_impl_trigger_ref",
            ),
        )
        op.create_index(
            "ix_rollback_executions_incident_id", "rollback_executions", ["incident_id"]
        )
        op.create_index(
            "ix_rollback_executions_patch_proposal_id",
            "rollback_executions",
            ["patch_proposal_id"],
        )
        op.create_index("ix_rollback_executions_status", "rollback_executions", ["status"])

    if "remediation_fingerprint" not in _columns("remediation_actions"):
        op.add_column(
            "remediation_actions",
            sa.Column("remediation_fingerprint", sa.String(length=128), nullable=True),
        )
        op.create_index(
            "ix_remediation_actions_fingerprint",
            "remediation_actions",
            ["remediation_fingerprint"],
        )

    if "remediation_fingerprint" not in _columns("verified_remediation_cases"):
        op.add_column(
            "verified_remediation_cases",
            sa.Column("remediation_fingerprint", sa.String(length=128), nullable=True),
        )
        op.create_index(
            "ix_verified_cases_fingerprint",
            "verified_remediation_cases",
            ["remediation_fingerprint"],
        )


def downgrade() -> None:
    if "remediation_fingerprint" in _columns("verified_remediation_cases"):
        op.drop_index("ix_verified_cases_fingerprint", table_name="verified_remediation_cases")
        op.drop_column("verified_remediation_cases", "remediation_fingerprint")
    if "remediation_fingerprint" in _columns("remediation_actions"):
        op.drop_index("ix_remediation_actions_fingerprint", table_name="remediation_actions")
        op.drop_column("remediation_actions", "remediation_fingerprint")
    if "rollback_executions" in _tables():
        op.drop_table("rollback_executions")
