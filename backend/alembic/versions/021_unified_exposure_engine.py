"""Unified exposure engine: alert grouping, live monitor state, correlation.

Revision ID: 021_unified_exposure_engine
Revises: 020_integrity_verification_mode

Additive support for Phases H-K of the core engine hardening work
(see docs/CORE_ENGINE_BASELINE_AUDIT.md, docs/LIVE_ALERT_GROUPING.md,
docs/LIVE_CORRELATION_MODEL.md):

* Phase I  - real alert grouping columns on `privacy_alerts`.
* Phase J  - `live_monitor_runtime_state` (durable Live Monitor control state).
* Phase K  - correlation columns on `normalized_events` and a durable
             `integration_events` table.

Uses inspector-based guards (IF NOT EXISTS style, following migration 012's
pattern) so this migration is safe to run both against a real database
upgrading from revision 020 and against a from-scratch database bootstrapped
by migration 001 from today's live models (which already has these columns).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "021_unified_exposure_engine"
down_revision: Union[str, None] = "020_integrity_verification_mode"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    # --- Phase I: real alert grouping on privacy_alerts ---
    alert_columns = {column["name"] for column in inspector.get_columns("privacy_alerts")}
    if "alert_group_key" not in alert_columns:
        op.add_column("privacy_alerts", sa.Column("alert_group_key", sa.String(80), nullable=True))
        op.create_index(
            "ix_privacy_alerts_alert_group_key", "privacy_alerts", ["alert_group_key"]
        )
    if "first_seen" not in alert_columns:
        op.add_column("privacy_alerts", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
        op.execute("UPDATE privacy_alerts SET first_seen = alert_time WHERE first_seen IS NULL")
    if "last_seen" not in alert_columns:
        op.add_column("privacy_alerts", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
        op.execute("UPDATE privacy_alerts SET last_seen = alert_time WHERE last_seen IS NULL")
    if "repeat_count" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column("repeat_count", sa.Integer(), server_default="1", nullable=False),
        )
    if "affected_trace_count" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column("affected_trace_count", sa.Integer(), server_default="1", nullable=False),
        )
    if "grouping_rule_version" not in alert_columns:
        op.add_column(
            "privacy_alerts", sa.Column("grouping_rule_version", sa.String(32), nullable=True)
        )
    if "exposure_location" not in alert_columns:
        op.add_column(
            "privacy_alerts", sa.Column("exposure_location", sa.String(64), nullable=True)
        )
    if "confidence_score" not in alert_columns:
        op.add_column("privacy_alerts", sa.Column("confidence_score", sa.Float(), nullable=True))
    if "confidence_level" not in alert_columns:
        op.add_column(
            "privacy_alerts", sa.Column("confidence_level", sa.String(16), nullable=True)
        )
    if "alert_findings" not in alert_columns:
        op.add_column(
            "privacy_alerts",
            sa.Column(
                "alert_findings",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
        )

    # --- Phase J: durable Live Monitor runtime state ---
    if "live_monitor_runtime_state" not in tables:
        op.create_table(
            "live_monitor_runtime_state",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("state_key", sa.String(64), nullable=False),
            sa.Column("running", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("mode", sa.String(64), server_default="http_ingestion", nullable=False),
            sa.Column("source_name", sa.String(255), nullable=True),
            sa.Column("environment", sa.String(64), nullable=True),
            sa.Column("safe_mode", sa.Boolean(), server_default="true", nullable=False),
            sa.Column("safety_status", sa.String(32), server_default="safe", nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_event_received_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_alert_created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("event_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("alert_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("session_id", sa.String(64), nullable=True),
            sa.Column(
                "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
            ),
            sa.UniqueConstraint("state_key"),
        )

    # --- Phase K: durable cross-source correlation on normalized_events ---
    event_columns = {column["name"] for column in inspector.get_columns("normalized_events")}
    for column_name, column_type, indexed in (
        ("trace_id", sa.String(128), True),
        ("request_id", sa.String(128), False),
        ("correlation_id", sa.String(128), True),
        ("transaction_reference_hash", sa.String(128), False),
        ("session_reference_hash", sa.String(128), False),
        ("deployment_version", sa.String(64), False),
        ("commit_reference", sa.String(128), False),
        ("configuration_version", sa.String(64), False),
        ("host_reference", sa.String(255), False),
    ):
        if column_name not in event_columns:
            op.add_column("normalized_events", sa.Column(column_name, column_type, nullable=True))
            if indexed:
                op.create_index(
                    f"ix_normalized_events_{column_name}", "normalized_events", [column_name]
                )

    # --- Phase K: durable integration_events table ---
    if "integration_events" not in tables:
        op.create_table(
            "integration_events",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("integration_event_id", sa.String(64), nullable=False),
            sa.Column("schema_version", sa.String(16), nullable=False),
            sa.Column("source_name", sa.String(255), nullable=True),
            sa.Column("source_tool", sa.String(128), nullable=True),
            sa.Column("source_type", sa.String(64), nullable=False),
            sa.Column("source_format", sa.String(64), nullable=False),
            sa.Column("external_alert_id", sa.String(255), nullable=True),
            sa.Column("external_incident_id", sa.String(255), nullable=True),
            sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
            ),
            sa.Column("service_name", sa.String(255), nullable=True),
            sa.Column("endpoint", sa.String(512), nullable=True),
            sa.Column("environment", sa.String(64), nullable=True),
            sa.Column("event_type", sa.String(128), nullable=True),
            sa.Column("sensitive_type", sa.String(128), nullable=True),
            sa.Column("masked_value", sa.String(512), nullable=True),
            sa.Column("severity", sa.String(32), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("message_summary", sa.Text(), nullable=True),
            sa.Column("evidence_reference", sa.String(64), nullable=True),
            sa.Column("trace_id", sa.String(128), nullable=True),
            sa.Column(
                "tags",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column("raw_payload_hash", sa.String(128), nullable=True),
            sa.Column("safety_status", sa.String(32), server_default="safe", nullable=False),
            sa.Column(
                "sensitive_types",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "masked_values",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "correlation_keys",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column("linked_alert_id", sa.String(64), nullable=True),
            sa.Column("linked_incident_id", sa.String(64), nullable=True),
            sa.Column(
                "missing_metadata",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "recommendations",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default=sa.text("'[]'::jsonb"),
                nullable=False,
            ),
            sa.Column("correlation_strength", sa.String(32), nullable=True),
            sa.Column("warning", sa.Text(), nullable=True),
            sa.Column(
                "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
            ),
            sa.UniqueConstraint("integration_event_id"),
        )
        op.create_index(
            "ix_integration_events_integration_event_id",
            "integration_events",
            ["integration_event_id"],
        )


def downgrade() -> None:
    op.drop_index("ix_integration_events_integration_event_id", table_name="integration_events")
    op.drop_table("integration_events")

    for column_name in (
        "host_reference",
        "configuration_version",
        "commit_reference",
        "deployment_version",
        "session_reference_hash",
        "transaction_reference_hash",
        "correlation_id",
        "request_id",
        "trace_id",
    ):
        if column_name in ("trace_id", "correlation_id"):
            op.drop_index(f"ix_normalized_events_{column_name}", table_name="normalized_events")
        op.drop_column("normalized_events", column_name)

    op.drop_table("live_monitor_runtime_state")

    for column_name in (
        "alert_findings",
        "confidence_level",
        "confidence_score",
        "exposure_location",
        "grouping_rule_version",
        "affected_trace_count",
        "repeat_count",
        "last_seen",
        "first_seen",
    ):
        op.drop_column("privacy_alerts", column_name)
    op.drop_index("ix_privacy_alerts_alert_group_key", table_name="privacy_alerts")
    op.drop_column("privacy_alerts", "alert_group_key")
