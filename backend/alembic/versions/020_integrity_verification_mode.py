"""Additive Phase 6 integrity verification mode column.

Revision ID: 020_integrity_verification_mode
Revises: 019_root_cause_evidence_roles
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "020_integrity_verification_mode"
down_revision: Union[str, None] = "019_root_cause_evidence_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "integrity_verification_runs",
        sa.Column(
            "verification_mode",
            sa.String(64),
            server_default="global_with_scope_membership",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("integrity_verification_runs", "verification_mode")
