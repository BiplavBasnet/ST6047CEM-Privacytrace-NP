"""Alembic revision 035 — bootstrap, verification method, password reset.

Revision ID: 035_onboarding_hardening
Revises: 034_organisation_verification
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "035_onboarding_hardening"
down_revision: Union[str, None] = "034_organisation_verification"
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
    cols = _columns("deployment_setup")
    if "bootstrap_consumed_at" not in cols:
        op.add_column(
            "deployment_setup",
            sa.Column("bootstrap_consumed_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "bootstrap_token_hash" not in cols:
        op.add_column(
            "deployment_setup",
            sa.Column("bootstrap_token_hash", sa.String(length=64), nullable=True),
        )

    org_cols = _columns("organisations")
    if "overall_verification_method" not in org_cols:
        op.add_column(
            "organisations",
            sa.Column("overall_verification_method", sa.String(length=64), nullable=True),
        )
    if "legal_verification_method" not in org_cols:
        op.add_column(
            "organisations",
            sa.Column("legal_verification_method", sa.String(length=64), nullable=True),
        )

    review_cols = _columns("organisation_manual_reviews")
    if "verification_method" not in review_cols:
        op.add_column(
            "organisation_manual_reviews",
            sa.Column("verification_method", sa.String(length=64), nullable=True),
        )
    if "official_source" not in review_cols:
        op.add_column(
            "organisation_manual_reviews",
            sa.Column("official_source", sa.String(length=64), nullable=True),
        )
    if "reference_safe" not in review_cols:
        op.add_column(
            "organisation_manual_reviews",
            sa.Column("reference_safe", sa.String(length=255), nullable=True),
        )

    if "password_reset_tokens" not in _tables():
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("token_hash", name="uq_password_reset_token_hash"),
        )
        op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
        op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    if "password_reset_tokens" in _tables():
        op.drop_table("password_reset_tokens")
    for name in ("reference_safe", "official_source", "verification_method"):
        if name in _columns("organisation_manual_reviews"):
            op.drop_column("organisation_manual_reviews", name)
    for name in ("legal_verification_method", "overall_verification_method"):
        if name in _columns("organisations"):
            op.drop_column("organisations", name)
    for name in ("bootstrap_token_hash", "bootstrap_consumed_at"):
        if name in _columns("deployment_setup"):
            op.drop_column("deployment_setup", name)
