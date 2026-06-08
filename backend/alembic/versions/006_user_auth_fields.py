"""Add authentication fields to users table

Revision ID: 006_user_auth_fields
Revises: 005_phase10_evaluation
Create Date: 2026-05-15

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006_user_auth_fields"
down_revision: Union[str, None] = "005_phase10_evaluation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _user_columns() -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {column["name"] for column in inspector.get_columns("users")}


def upgrade() -> None:
    existing = _user_columns()
    if "password_hash" not in existing:
        op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=True))
    if "is_active" not in existing:
        op.add_column(
            "users",
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        )
    if "last_login_at" not in existing:
        op.add_column(
            "users",
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "updated_at" not in existing:
        op.add_column(
            "users",
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )


def downgrade() -> None:
    existing = _user_columns()
    if "updated_at" in existing:
        op.drop_column("users", "updated_at")
    if "last_login_at" in existing:
        op.drop_column("users", "last_login_at")
    if "is_active" in existing:
        op.drop_column("users", "is_active")
    if "password_hash" in existing:
        op.drop_column("users", "password_hash")
