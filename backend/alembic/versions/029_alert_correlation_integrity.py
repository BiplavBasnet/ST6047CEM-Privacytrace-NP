"""Harden live alert grouping, correlation fingerprints, and event time.

Revision ID: 029_alert_correlation_integrity
Revises: 028_controlled_retest_verification
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "029_alert_correlation_integrity"
down_revision: Union[str, None] = "028_controlled_retest_verification"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(inspector: sa.Inspector, table: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("Migration 029 requires PostgreSQL.")
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "privacy_alerts" in tables:
        cols = _columns(inspector, "privacy_alerts")
        for name, column in (
            ("trace_count_quality", sa.Column("trace_count_quality", sa.String(32), nullable=False, server_default="unavailable")),
            ("first_source_event_time", sa.Column("first_source_event_time", sa.DateTime(timezone=True), nullable=True)),
            ("last_source_event_time", sa.Column("last_source_event_time", sa.DateTime(timezone=True), nullable=True)),
            ("source_time_quality", sa.Column("source_time_quality", sa.String(32), nullable=False, server_default="legacy_reported")),
            ("source_time_inferred", sa.Column("source_time_inferred", sa.Boolean(), nullable=False, server_default=sa.text("false"))),
            ("source_timezone_name", sa.Column("source_timezone_name", sa.String(64), nullable=True)),
        ):
            if name not in cols:
                op.add_column("privacy_alerts", column)
        op.execute("UPDATE privacy_alerts SET first_source_event_time = COALESCE(first_seen, alert_time), last_source_event_time = COALESCE(last_seen, alert_time) WHERE first_source_event_time IS NULL")
        op.execute("UPDATE privacy_alerts SET first_seen = received_at, last_seen = received_at, affected_trace_count = NULL, trace_count_quality = 'unavailable'")
        op.alter_column("privacy_alerts", "source_time_quality", existing_type=sa.String(32), nullable=False, server_default="inferred")
        op.alter_column("privacy_alerts", "source_time_inferred", existing_type=sa.Boolean(), nullable=False, server_default=sa.text("true"))
        op.execute("UPDATE privacy_alerts SET correlation_keys = correlation_keys - ARRAY['trace_id','request_id','correlation_id','transaction_reference_hash','session_reference_hash']::text[] WHERE correlation_keys IS NOT NULL")
        op.alter_column("privacy_alerts", "affected_trace_count", existing_type=sa.Integer(), nullable=True, server_default=None)

    if "alert_trace_references" in tables:
        cols = _columns(inspector, "alert_trace_references")
        if "fingerprint_method" not in cols:
            op.add_column("alert_trace_references", sa.Column("fingerprint_method", sa.String(32), nullable=True))
        if "fingerprint_version" not in cols:
            op.add_column("alert_trace_references", sa.Column("fingerprint_version", sa.String(16), nullable=True))
        # Legacy values may be raw or unkeyed; retain history but exclude them from trusted counts.
        op.execute("UPDATE alert_trace_references SET fingerprint_method = 'legacy_untrusted', fingerprint_version = 'legacy' WHERE fingerprint_method IS NULL")
        op.alter_column("alert_trace_references", "fingerprint_method", existing_type=sa.String(32), nullable=False)
        op.alter_column("alert_trace_references", "fingerprint_version", existing_type=sa.String(16), nullable=False)

    for table in ("normalized_events", "integration_events"):
        if table not in tables:
            continue
        cols = _columns(inspector, table)
        additions = [
            ("trace_fingerprint", sa.String(128)),
            ("correlation_fingerprint_method", sa.String(32)),
            ("correlation_fingerprint_version", sa.String(16)),
        ]
        if table == "normalized_events":
            additions += [("request_fingerprint", sa.String(128)), ("correlation_fingerprint", sa.String(128))]
        else:
            additions += [
                ("source_time_quality", sa.String(32)),
                ("source_time_inferred", sa.Boolean()),
                ("source_timezone_name", sa.String(64)),
            ]
        for name, kind in additions:
            if name not in cols:
                op.add_column(table, sa.Column(name, kind, nullable=True))
        raw_columns = [name for name in ("trace_id", "request_id", "correlation_id", "transaction_reference_hash", "session_reference_hash") if name in cols]
        if raw_columns:
            op.execute(sa.text(f"UPDATE {table} SET " + ", ".join(f"{name} = NULL" for name in raw_columns)))

    if "integration_events" in tables:
        op.execute("UPDATE integration_events SET source_time_quality = CASE WHEN event_time IS NULL THEN 'inferred' ELSE 'legacy_reported' END, source_time_inferred = (event_time IS NULL) WHERE source_time_quality IS NULL")
        op.alter_column("integration_events", "source_time_quality", existing_type=sa.String(32), nullable=False, server_default="inferred")
        op.alter_column("integration_events", "source_time_inferred", existing_type=sa.Boolean(), nullable=False, server_default=sa.text("true"))
        op.execute("UPDATE integration_events SET correlation_keys = correlation_keys - ARRAY['trace_id','request_id','correlation_id','transaction_reference_hash','session_reference_hash']::text[]")


def downgrade() -> None:
    # Security cleanup of legacy raw identifiers is intentionally irreversible.
    for table, columns in (
        ("integration_events", ("source_timezone_name", "source_time_inferred", "source_time_quality", "correlation_fingerprint_version", "correlation_fingerprint_method", "trace_fingerprint")),
        ("normalized_events", ("correlation_fingerprint", "request_fingerprint", "trace_fingerprint", "correlation_fingerprint_version", "correlation_fingerprint_method")),
        ("alert_trace_references", ("fingerprint_version", "fingerprint_method")),
        ("privacy_alerts", ("source_timezone_name", "source_time_inferred", "source_time_quality", "last_source_event_time", "first_source_event_time", "trace_count_quality")),
    ):
        inspector = sa.inspect(op.get_bind())
        if table not in inspector.get_table_names():
            continue
        existing = _columns(inspector, table)
        for column in columns:
            if column in existing:
                op.drop_column(table, column)
