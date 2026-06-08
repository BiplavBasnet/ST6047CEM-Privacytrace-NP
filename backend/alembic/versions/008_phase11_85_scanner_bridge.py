"""Phase 11.85 ScannerBridge-NP scanner evidence records

Revision ID: 008_phase11_85_scanner_bridge
Revises: 007_phase11_7_crypto
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "008_phase11_85_scanner_bridge"
down_revision: Union[str, None] = "007_phase11_7_crypto"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("scanner_evidence_records"):
        return

    op.create_table(
        "scanner_evidence_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scanner_evidence_id", sa.String(length=64), nullable=False),
        sa.Column("import_evidence_id", sa.String(length=64), nullable=False),
        sa.Column("source_format", sa.String(length=64), nullable=False),
        sa.Column("scanner_category", sa.String(length=128), nullable=True),
        sa.Column("finding_type", sa.String(length=128), nullable=True),
        sa.Column("detector_name", sa.String(length=256), nullable=True),
        sa.Column("verification_status", sa.String(length=64), nullable=True),
        sa.Column(
            "severity",
            sa.Enum("low", "medium", "high", "critical", name="scanner_evidence_severity", native_enum=False),
            nullable=True,
        ),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("causal_relevance_score", sa.Float(), nullable=True),
        sa.Column("repository", sa.String(length=512), nullable=True),
        sa.Column("source_file", sa.String(length=1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("commit_id", sa.String(length=128), nullable=True),
        sa.Column("branch", sa.String(length=256), nullable=True),
        sa.Column("masked_value", sa.String(length=512), nullable=True),
        sa.Column("evidence_reference", sa.String(length=255), nullable=False),
        sa.Column("linked_evidence_id", sa.String(length=64), nullable=True),
        sa.Column("linked_incident_id", sa.String(length=64), nullable=True),
        sa.Column("service_hint", sa.String(length=255), nullable=True),
        sa.Column("endpoint_hint", sa.String(length=512), nullable=True),
        sa.Column("release_version_hint", sa.String(length=128), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("safety_status", sa.String(length=32), nullable=False),
        sa.Column("raw_payload_hash", sa.String(length=128), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("finding_fingerprint", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(["import_evidence_id"], ["evidence_files.evidence_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["linked_incident_id"], ["incidents.incident_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scanner_evidence_id"),
    )
    op.create_index(
        "ix_scanner_evidence_records_scanner_evidence_id",
        "scanner_evidence_records",
        ["scanner_evidence_id"],
        unique=True,
    )
    op.create_index(
        "ix_scanner_evidence_records_import_evidence_id",
        "scanner_evidence_records",
        ["import_evidence_id"],
    )
    op.create_index(
        "ix_scanner_evidence_records_linked_incident_id",
        "scanner_evidence_records",
        ["linked_incident_id"],
    )
    op.create_index(
        "ix_scanner_evidence_records_finding_fingerprint",
        "scanner_evidence_records",
        ["finding_fingerprint"],
    )


def downgrade() -> None:
    op.drop_index("ix_scanner_evidence_records_finding_fingerprint", table_name="scanner_evidence_records")
    op.drop_index("ix_scanner_evidence_records_linked_incident_id", table_name="scanner_evidence_records")
    op.drop_index("ix_scanner_evidence_records_import_evidence_id", table_name="scanner_evidence_records")
    op.drop_index("ix_scanner_evidence_records_scanner_evidence_id", table_name="scanner_evidence_records")
    op.drop_table("scanner_evidence_records")
    op.execute("DROP TYPE IF EXISTS scanner_evidence_severity")
