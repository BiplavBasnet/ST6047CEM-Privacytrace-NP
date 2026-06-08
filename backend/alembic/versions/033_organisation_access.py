"""Alembic revision 033 — organisation isolation for one-deployment thesis model.

Revision ID: 033_organisation_access
Revises: 032_current_remediation_branch
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "033_organisation_access"
down_revision: Union[str, None] = "032_current_remediation_branch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _fk_names(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {fk.get("name") for fk in inspector.get_foreign_keys(table) if fk.get("name")}


def _ensure_organisation_id(table: str, constraint: str, ondelete: str) -> None:
    if table not in _tables():
        return
    if "organisation_id" not in _columns(table):
        op.add_column(table, sa.Column("organisation_id", sa.Integer(), nullable=True))
        op.create_index(f"ix_{table}_organisation_id", table, ["organisation_id"])
    inspector = sa.inspect(op.get_bind())
    index_names = {idx["name"] for idx in inspector.get_indexes(table)}
    if f"ix_{table}_organisation_id" not in index_names:
        op.create_index(f"ix_{table}_organisation_id", table, ["organisation_id"])
    if constraint not in _fk_names(table):
        op.create_foreign_key(
            constraint,
            table,
            "organisations",
            ["organisation_id"],
            ["id"],
            ondelete=ondelete,
        )


def upgrade() -> None:
    tables = _tables()
    if "organisations" not in tables:
        op.create_table(
            "organisations",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("slug", sa.String(length=128), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("deployment_slot", sa.Integer(), nullable=False, server_default="1"),
            sa.Column(
                "approved_email_domains",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("slug", name="uq_organisations_slug"),
            sa.UniqueConstraint("deployment_slot", name="uq_organisations_deployment_slot"),
        )
        op.create_index("ix_organisations_slug", "organisations", ["slug"], unique=True)

    if "organisation_memberships" not in _tables():
        op.create_table(
            "organisation_memberships",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("organisation_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("role", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("approved_by", sa.Integer(), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["organisation_id"], ["organisations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("organisation_id", "user_id", name="uq_org_membership_user"),
        )
        op.create_index("ix_organisation_memberships_organisation_id", "organisation_memberships", ["organisation_id"])
        op.create_index("ix_organisation_memberships_user_id", "organisation_memberships", ["user_id"])
        op.create_index("ix_organisation_memberships_status", "organisation_memberships", ["status"])

    if "organisation_invitations" not in _tables():
        op.create_table(
            "organisation_invitations",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("organisation_id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=64), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("invited_by", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.ForeignKeyConstraint(["organisation_id"], ["organisations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["invited_by"], ["users.id"], ondelete="RESTRICT"),
            sa.UniqueConstraint("token_hash", name="uq_organisation_invitations_token_hash"),
        )
        op.create_index("ix_organisation_invitations_organisation_id", "organisation_invitations", ["organisation_id"])
        op.create_index("ix_organisation_invitations_email", "organisation_invitations", ["email"])
        op.create_index("ix_organisation_invitations_token_hash", "organisation_invitations", ["token_hash"], unique=True)
        op.create_index("ix_organisation_invitations_status", "organisation_invitations", ["status"])
        op.create_index(
            "uq_org_pending_invite_email",
            "organisation_invitations",
            ["organisation_id", "email"],
            unique=True,
            postgresql_where=sa.text("status = 'pending'"),
        )

    if "deployment_setup" not in _tables():
        op.create_table(
            "deployment_setup",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("completed", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_by_user_id", sa.Integer(), nullable=True),
            sa.Column("organisation_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["completed_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["organisation_id"], ["organisations.id"], ondelete="SET NULL"),
        )

    users_cols = _columns("users")
    if "token_version" not in users_cols:
        op.add_column(
            "users",
            sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
        )

    _ensure_organisation_id("incidents", "fk_incidents_organisation_id", "RESTRICT")
    _ensure_organisation_id("audit_logs", "fk_audit_logs_organisation_id", "SET NULL")
    _ensure_organisation_id("integration_tokens", "fk_integration_tokens_organisation_id", "RESTRICT")


def downgrade() -> None:
    tables = _tables()
    if "organisation_id" in _columns("integration_tokens"):
        op.drop_constraint("fk_integration_tokens_organisation_id", "integration_tokens", type_="foreignkey")
        op.drop_index("ix_integration_tokens_organisation_id", table_name="integration_tokens")
        op.drop_column("integration_tokens", "organisation_id")
    if "organisation_id" in _columns("audit_logs"):
        op.drop_constraint("fk_audit_logs_organisation_id", "audit_logs", type_="foreignkey")
        op.drop_index("ix_audit_logs_organisation_id", table_name="audit_logs")
        op.drop_column("audit_logs", "organisation_id")
    if "organisation_id" in _columns("incidents"):
        op.drop_constraint("fk_incidents_organisation_id", "incidents", type_="foreignkey")
        op.drop_index("ix_incidents_organisation_id", table_name="incidents")
        op.drop_column("incidents", "organisation_id")
    if "token_version" in _columns("users"):
        op.drop_column("users", "token_version")
    if "deployment_setup" in tables:
        op.drop_table("deployment_setup")
    if "organisation_invitations" in tables:
        op.drop_table("organisation_invitations")
    if "organisation_memberships" in tables:
        op.drop_table("organisation_memberships")
    if "organisations" in tables:
        op.drop_table("organisations")
