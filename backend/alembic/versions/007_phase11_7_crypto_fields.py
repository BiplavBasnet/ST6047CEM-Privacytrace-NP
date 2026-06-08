"""Phase 11.7 crypto at-rest fields

Revision ID: 007_phase11_7_crypto
Revises: 006_user_auth_fields
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "007_phase11_7_crypto"
down_revision: Union[str, None] = "006_user_auth_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {c["name"] for c in inspector.get_columns(table)}


def _add_col(table: str, name: str, column: sa.Column) -> None:
    if name not in _columns(table):
        op.add_column(table, column)


def upgrade() -> None:
    _add_col("users", "password_hash_algorithm", sa.Column("password_hash_algorithm", sa.String(32), nullable=True))
    _add_col("users", "password_updated_at", sa.Column("password_updated_at", sa.DateTime(timezone=True), nullable=True))

    _add_col("audit_logs", "details_encrypted", sa.Column("details_encrypted", postgresql.JSONB(), nullable=True))
    _add_col("audit_logs", "details_crypto_metadata", sa.Column("details_crypto_metadata", postgresql.JSONB(), nullable=True))
    _add_col(
        "audit_logs",
        "is_encrypted",
        sa.Column("is_encrypted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    _add_col("reports", "content_encrypted", sa.Column("content_encrypted", postgresql.JSONB(), nullable=True))
    _add_col("reports", "content_crypto_metadata", sa.Column("content_crypto_metadata", postgresql.JSONB(), nullable=True))
    _add_col(
        "reports",
        "is_encrypted",
        sa.Column("is_encrypted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    _add_col("llm_reports", "output_encrypted", sa.Column("output_encrypted", postgresql.JSONB(), nullable=True))
    _add_col("llm_reports", "output_crypto_metadata", sa.Column("output_crypto_metadata", postgresql.JSONB(), nullable=True))
    _add_col(
        "llm_reports",
        "is_encrypted",
        sa.Column("is_encrypted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.alter_column("llm_reports", "output_json", existing_type=postgresql.JSONB(), nullable=True)

    _add_col("evidence_files", "encrypted_file_path", sa.Column("encrypted_file_path", sa.String(512), nullable=True))
    _add_col("evidence_files", "file_crypto_metadata", sa.Column("file_crypto_metadata", postgresql.JSONB(), nullable=True))
    _add_col(
        "evidence_files",
        "is_encrypted",
        sa.Column("is_encrypted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    for table, cols in (
        ("evidence_files", ("is_encrypted", "file_crypto_metadata", "encrypted_file_path")),
        ("llm_reports", ("is_encrypted", "output_crypto_metadata", "output_encrypted")),
        ("reports", ("is_encrypted", "content_crypto_metadata", "content_encrypted")),
        ("audit_logs", ("is_encrypted", "details_crypto_metadata", "details_encrypted")),
        ("users", ("password_updated_at", "password_hash_algorithm")),
    ):
        existing = _columns(table)
        for col in cols:
            if col in existing:
                op.drop_column(table, col)
