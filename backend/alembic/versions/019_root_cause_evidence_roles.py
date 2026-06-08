"""Additive Phase 4 root-cause evidence role columns.

Revision ID: 019_root_cause_evidence_roles
Revises: 018_stabilisation_hardening
"""

from typing import Sequence, Union

from alembic import op

revision: str = "019_root_cause_evidence_roles"
down_revision: Union[str, None] = "018_stabilisation_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# root_cause_scores is not one of the tables migration 001 creates from a
# historical column snapshot; it is created from the live ORM model, so a
# from-scratch database build already has these columns by the time this
# migration runs. "IF NOT EXISTS" keeps this migration correct both for that
# from-scratch case and for real databases upgrading from revision 018, where
# the columns genuinely do not exist yet.
def upgrade() -> None:
    op.execute(
        "ALTER TABLE root_cause_scores "
        "ADD COLUMN IF NOT EXISTS context_evidence_ids JSONB NOT NULL DEFAULT '[]'"
    )
    op.execute(
        "ALTER TABLE root_cause_scores "
        "ADD COLUMN IF NOT EXISTS remediation_evidence_ids JSONB NOT NULL DEFAULT '[]'"
    )
    op.execute(
        "ALTER TABLE root_cause_scores "
        "ADD COLUMN IF NOT EXISTS retest_evidence_ids JSONB NOT NULL DEFAULT '[]'"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE root_cause_scores DROP COLUMN IF EXISTS retest_evidence_ids")
    op.execute("ALTER TABLE root_cause_scores DROP COLUMN IF EXISTS remediation_evidence_ids")
    op.execute("ALTER TABLE root_cause_scores DROP COLUMN IF EXISTS context_evidence_ids")
