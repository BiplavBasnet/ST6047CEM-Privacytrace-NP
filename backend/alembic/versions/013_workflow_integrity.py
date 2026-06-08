"""Workflow state, remediation, review drafts, and CI/CD evidence.

Revision ID: 013_workflow_integrity
Revises: 012_universal_integration_gw
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "013_workflow_integrity"
down_revision: Union[str, None] = "012_universal_integration_gw"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "review_drafts" not in tables:
        op.create_table(
        "review_drafts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("selected_decision", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence_checklist", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence_relied_on", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence_limitations", sa.Text(), nullable=True),
        sa.Column("missing_evidence_notes", sa.Text(), nullable=True),
        sa.Column("missing_evidence_acknowledged", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("last_updated_by", sa.Integer(), nullable=True),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_updated_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("incident_id"),
        )
    review_draft_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("review_drafts")}
    if "ix_review_drafts_incident_id" not in review_draft_indexes:
        op.create_index("ix_review_drafts_incident_id", "review_drafts", ["incident_id"], unique=True)

    if "remediation_actions" not in tables:
        op.create_table(
        "remediation_actions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("remediation_action_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("action_description", sa.Text(), nullable=False),
        sa.Column("affected_component", sa.String(length=255), nullable=False),
        sa.Column("assigned_owner", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("target_date", sa.Date(), nullable=True),
        sa.Column("retest_required", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("completion_notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("remediation_action_id"),
        )
    remediation_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("remediation_actions")}
    if "ix_remediation_actions_incident_id" not in remediation_indexes:
        op.create_index("ix_remediation_actions_incident_id", "remediation_actions", ["incident_id"])
    if "ix_remediation_actions_action_id" not in remediation_indexes:
        op.create_index("ix_remediation_actions_action_id", "remediation_actions", ["remediation_action_id"], unique=True)

    if "cicd_evidence" not in tables:
        op.create_table(
        "cicd_evidence",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cicd_evidence_id", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("service_name", sa.String(length=255), nullable=True),
        sa.Column("pipeline_id", sa.String(length=128), nullable=True),
        sa.Column("deployment_version", sa.String(length=128), nullable=True),
        sa.Column("commit_reference", sa.String(length=128), nullable=True),
        sa.Column("changed_file_paths_safe", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("change_categories", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("scan_summary_safe", sa.Text(), nullable=True),
        sa.Column("test_summary_safe", sa.Text(), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("raw_event_hash", sa.String(length=128), nullable=False),
        sa.Column("linked_incident_id", sa.String(length=64), nullable=True),
        sa.Column("safety_status", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["linked_incident_id"], ["incidents.incident_id"], ondelete="SET NULL"),
        sa.UniqueConstraint("cicd_evidence_id"),
        )
    cicd_indexes = {index["name"] for index in sa.inspect(bind).get_indexes("cicd_evidence")}
    for name, columns, unique in (
        ("ix_cicd_evidence_id", ["cicd_evidence_id"], True),
        ("ix_cicd_evidence_type", ["evidence_type"], False),
        ("ix_cicd_evidence_service", ["service_name"], False),
        ("ix_cicd_evidence_incident", ["linked_incident_id"], False),
    ):
        if name not in cicd_indexes:
            op.create_index(name, "cicd_evidence", columns, unique=unique)

    review_columns = {column["name"] for column in sa.inspect(bind).get_columns("review_decisions")}
    review_column_specs = (
        ("reason", sa.Column("reason", sa.Text(), nullable=True)),
        (
            "evidence_checklist",
            sa.Column(
                "evidence_checklist",
                postgresql.JSONB(),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
        ),
        (
            "evidence_relied_on",
            sa.Column(
                "evidence_relied_on",
                postgresql.JSONB(),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
        ),
        ("evidence_limitations", sa.Column("evidence_limitations", sa.Text(), nullable=True)),
        (
            "missing_evidence_acknowledged",
            sa.Column(
                "missing_evidence_acknowledged",
                sa.Boolean(),
                server_default="false",
                nullable=False,
            ),
        ),
    )
    for name, column in review_column_specs:
        if name not in review_columns:
            op.add_column("review_decisions", column)


def downgrade() -> None:
    op.drop_column("review_decisions", "missing_evidence_acknowledged")
    op.drop_column("review_decisions", "evidence_limitations")
    op.drop_column("review_decisions", "evidence_relied_on")
    op.drop_column("review_decisions", "evidence_checklist")
    op.drop_column("review_decisions", "reason")
    op.drop_table("cicd_evidence")
    op.drop_table("remediation_actions")
    op.drop_table("review_drafts")
