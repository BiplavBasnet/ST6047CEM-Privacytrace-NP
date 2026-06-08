"""Root-cause analysis versioning + staleness columns on root_cause_scores.

Revision ID: 022_root_cause_versioning
Revises: 021_unified_exposure_engine

Additive support for Phase N of the core engine hardening work (see
docs/CORE_ENGINE_BASELINE_AUDIT.md, docs/ROOT_CAUSE_ANALYSIS_VERSIONING.md).

Re-analysing an incident now creates a new `analysis_id`/`analysis_version`
batch instead of deleting the previous one; the previous batch is marked
`superseded_by_analysis_id` + `stale`. New evidence (a detection, a linked
alert, CI/CD evidence, or scanner evidence) marks the *current* batch stale
without creating a new version, so a human analyst always sees an explicit
"this ranking may be outdated" signal before re-running analysis.

Uses inspector-based `has_column` guards (matching migration 021's pattern)
so this migration is safe both against a real database upgrading from
revision 021 and against a from-scratch database bootstrapped by migration
001 from today's live models (which already has these columns).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "022_root_cause_versioning"
down_revision: Union[str, None] = "021_unified_exposure_engine"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "root_cause_scores"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns(_TABLE)}

    if "analysis_id" not in columns:
        op.add_column(_TABLE, sa.Column("analysis_id", sa.String(64), nullable=True))
        op.create_index("ix_root_cause_scores_analysis_id", _TABLE, ["analysis_id"])
    if "analysis_version" not in columns:
        op.add_column(
            _TABLE,
            sa.Column("analysis_version", sa.Integer(), server_default="1", nullable=False),
        )
    if "rules_version" not in columns:
        op.add_column(_TABLE, sa.Column("rules_version", sa.String(128), nullable=True))
    if "evidence_snapshot_hash" not in columns:
        op.add_column(_TABLE, sa.Column("evidence_snapshot_hash", sa.String(64), nullable=True))
    if "analysed_at" not in columns:
        op.add_column(_TABLE, sa.Column("analysed_at", sa.DateTime(timezone=True), nullable=True))
        op.execute(f"UPDATE {_TABLE} SET analysed_at = created_at WHERE analysed_at IS NULL")
    if "stale" not in columns:
        op.add_column(
            _TABLE, sa.Column("stale", sa.Boolean(), server_default="false", nullable=False)
        )
    if "stale_reason" not in columns:
        op.add_column(_TABLE, sa.Column("stale_reason", sa.Text(), nullable=True))
    if "superseded_by_analysis_id" not in columns:
        op.add_column(
            _TABLE, sa.Column("superseded_by_analysis_id", sa.String(64), nullable=True)
        )

    # Backfill a distinct analysis_id per pre-existing (incident_id, rank==1)
    # batch so historical rows created before this migration still group
    # sensibly under `list_root_cause_scores(..., include_history=True)`.
    op.execute(
        f"""
        UPDATE {_TABLE}
        SET analysis_id = 'RCA-ANALYSIS-LEGACY-' || incident_id
        WHERE analysis_id IS NULL
        """
    )


def downgrade() -> None:
    for column_name in (
        "superseded_by_analysis_id",
        "stale_reason",
        "stale",
        "analysed_at",
        "evidence_snapshot_hash",
        "rules_version",
        "analysis_version",
    ):
        op.drop_column(_TABLE, column_name)
    op.drop_index("ix_root_cause_scores_analysis_id", table_name=_TABLE)
    op.drop_column(_TABLE, "analysis_id")
