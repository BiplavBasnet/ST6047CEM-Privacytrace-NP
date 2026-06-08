"""Alembic revision 034 — organisation legal/domain/email verification.

Revision ID: 034_organisation_verification
Revises: 033_organisation_access
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "034_organisation_verification"
down_revision: Union[str, None] = "033_organisation_access"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    cols = _columns("organisations")
    additions = [
        ("legal_name", sa.Column("legal_name", sa.String(length=255), nullable=True)),
        ("registration_number", sa.Column("registration_number", sa.String(length=64), nullable=True)),
        ("pan_number", sa.Column("pan_number", sa.String(length=64), nullable=True)),
        ("registered_address", sa.Column("registered_address", sa.Text(), nullable=True)),
        ("website_domain", sa.Column("website_domain", sa.String(length=255), nullable=True)),
        (
            "legal_verification_status",
            sa.Column("legal_verification_status", sa.String(length=32), nullable=False, server_default="unverified"),
        ),
        (
            "pan_verification_status",
            sa.Column("pan_verification_status", sa.String(length=32), nullable=False, server_default="unverified"),
        ),
        (
            "domain_verification_status",
            sa.Column("domain_verification_status", sa.String(length=32), nullable=False, server_default="unverified"),
        ),
        (
            "admin_email_verification_status",
            sa.Column(
                "admin_email_verification_status",
                sa.String(length=32),
                nullable=False,
                server_default="unverified",
            ),
        ),
        (
            "overall_verification_status",
            sa.Column(
                "overall_verification_status",
                sa.String(length=32),
                nullable=False,
                server_default="unverified",
            ),
        ),
        ("legal_verification_source", sa.Column("legal_verification_source", sa.String(length=64), nullable=True)),
        (
            "legal_verification_reference",
            sa.Column("legal_verification_reference", sa.String(length=255), nullable=True),
        ),
        ("pan_verification_method", sa.Column("pan_verification_method", sa.String(length=64), nullable=True)),
        (
            "pan_verification_reference",
            sa.Column("pan_verification_reference", sa.String(length=255), nullable=True),
        ),
        ("verified_at", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True)),
        ("verified_by", sa.Column("verified_by", sa.Integer(), nullable=True)),
        ("verification_notes_safe", sa.Column("verification_notes_safe", sa.Text(), nullable=True)),
        (
            "verification_mode",
            sa.Column("verification_mode", sa.String(length=32), nullable=False, server_default="manual"),
        ),
        (
            "demo_verification_simulated",
            sa.Column("demo_verification_simulated", sa.Boolean(), nullable=False, server_default="false"),
        ),
        (
            "allow_external_admin_email",
            sa.Column("allow_external_admin_email", sa.Boolean(), nullable=False, server_default="false"),
        ),
    ]
    for name, column in additions:
        if name not in cols:
            op.add_column("organisations", column)
    if "verified_by" in _columns("organisations"):
        inspector = sa.inspect(op.get_bind())
        fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("organisations") if fk.get("name")}
        if "fk_organisations_verified_by" not in fk_names:
            op.create_foreign_key(
                "fk_organisations_verified_by",
                "organisations",
                "users",
                ["verified_by"],
                ["id"],
                ondelete="SET NULL",
            )
    index_names = {idx["name"] for idx in sa.inspect(op.get_bind()).get_indexes("organisations")}
    if "ix_organisations_overall_verification_status" not in index_names:
        op.create_index(
            "ix_organisations_overall_verification_status",
            "organisations",
            ["overall_verification_status"],
        )

    if "admin_email_verified" not in _columns("users"):
        op.add_column(
            "users",
            sa.Column("admin_email_verified", sa.Boolean(), nullable=False, server_default="false"),
        )

    if "organisation_domain_challenges" not in _tables():
        op.create_table(
            "organisation_domain_challenges",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("organisation_id", sa.Integer(), nullable=False),
            sa.Column("domain", sa.String(length=255), nullable=False),
            sa.Column("challenge_hash", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.ForeignKeyConstraint(["organisation_id"], ["organisations.id"], ondelete="CASCADE"),
        )
        op.create_index(
            "ix_organisation_domain_challenges_organisation_id",
            "organisation_domain_challenges",
            ["organisation_id"],
        )
        op.create_index(
            "ix_organisation_domain_challenges_status",
            "organisation_domain_challenges",
            ["status"],
        )

    if "organisation_email_verifications" not in _tables():
        op.create_table(
            "organisation_email_verifications",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("organisation_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.ForeignKeyConstraint(["organisation_id"], ["organisations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("token_hash", name="uq_org_email_verification_token_hash"),
        )
        op.create_index(
            "ix_organisation_email_verifications_organisation_id",
            "organisation_email_verifications",
            ["organisation_id"],
        )
        op.create_index(
            "ix_organisation_email_verifications_user_id",
            "organisation_email_verifications",
            ["user_id"],
        )
        op.create_index(
            "ix_organisation_email_verifications_token_hash",
            "organisation_email_verifications",
            ["token_hash"],
            unique=True,
        )

    if "organisation_manual_reviews" not in _tables():
        op.create_table(
            "organisation_manual_reviews",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("organisation_id", sa.Integer(), nullable=False),
            sa.Column("reason", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
            sa.Column("requested_by", sa.Integer(), nullable=True),
            sa.Column("reviewer_id", sa.Integer(), nullable=True),
            sa.Column("decision_notes_safe", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["organisation_id"], ["organisations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"], ondelete="SET NULL"),
        )
        op.create_index(
            "ix_organisation_manual_reviews_organisation_id",
            "organisation_manual_reviews",
            ["organisation_id"],
        )
        op.create_index(
            "ix_organisation_manual_reviews_status",
            "organisation_manual_reviews",
            ["status"],
        )


def downgrade() -> None:
    for table in (
        "organisation_manual_reviews",
        "organisation_email_verifications",
        "organisation_domain_challenges",
    ):
        if table in _tables():
            op.drop_table(table)
    if "admin_email_verified" in _columns("users"):
        op.drop_column("users", "admin_email_verified")
    for name in (
        "allow_external_admin_email",
        "demo_verification_simulated",
        "verification_mode",
        "verification_notes_safe",
        "verified_by",
        "verified_at",
        "pan_verification_reference",
        "pan_verification_method",
        "legal_verification_reference",
        "legal_verification_source",
        "overall_verification_status",
        "admin_email_verification_status",
        "domain_verification_status",
        "pan_verification_status",
        "legal_verification_status",
        "website_domain",
        "registered_address",
        "pan_number",
        "registration_number",
        "legal_name",
    ):
        if name in _columns("organisations"):
            op.drop_column("organisations", name)
