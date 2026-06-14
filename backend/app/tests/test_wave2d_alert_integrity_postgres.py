from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select, text

from app.database import SessionLocal
from app.config import get_settings
from app.models.enums import Severity
from app.models.integration_event import IntegrationEvent
from app.models.privacy_alert import PrivacyAlert
from app.models.workflow_verification import AlertTraceReference
from app.services import live_alert_grouping_service, live_alert_service

pytestmark = pytest.mark.usefixtures("migrated_db")


def test_concurrent_first_group_claim_creates_one_alert_with_two_occurrences():
    group_key = f"AGRP-TEST-{uuid.uuid4().hex}"

    def ingest() -> None:
        with SessionLocal() as db, db.begin():
            observed = datetime.now(UTC)
            live_alert_grouping_service.acquire_group_claim(db, group_key)
            alert = live_alert_grouping_service.find_open_alert(db, group_key, at=observed)
            if alert:
                live_alert_grouping_service.register_recurrence(db, alert, observed_at=observed)
            else:
                live_alert_service.create_alert(
                    db,
                    alert_time=observed,
                    observed_at=observed,
                    source_type="api_log",
                    source_name="wave2d-test",
                    source_format="generic_json",
                    service_name="wave2d-test",
                    endpoint="/synthetic",
                    environment="test",
                    severity=Severity.MEDIUM,
                    sensitive_types=["phone_number"],
                    masked_values=["98******67"],
                    raw_event_hash="sha256:synthetic",
                    alert_summary="safe synthetic alert",
                    alert_group_key=group_key,
                )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: ingest(), range(2)))

    with SessionLocal() as db, db.begin():
        rows = list(db.scalars(select(PrivacyAlert).where(PrivacyAlert.alert_group_key == group_key)))
        assert len(rows) == 1
        assert rows[0].repeat_count == 2
        db.execute(delete(PrivacyAlert).where(PrivacyAlert.alert_group_key == group_key))


def test_migration_029_columns_are_present():
    with SessionLocal() as db:
        assert db.bind is not None and db.bind.dialect.name == "postgresql"
        from sqlalchemy import inspect

        inspector = inspect(db.bind)
        privacy_columns = {item["name"] for item in inspector.get_columns("privacy_alerts")}
        assert {"trace_count_quality", "first_source_event_time", "last_source_event_time"} <= privacy_columns
        trace_columns = {item["name"] for item in inspector.get_columns("alert_trace_references")}
        assert {"fingerprint_method", "fingerprint_version"} <= trace_columns


def test_upgrade_028_to_029_preserves_source_bounds_and_quarantines_legacy_data():
    pytest.skip(
        "In-place 028↔029 replay stamps over later revisions and is unsafe at head 033; "
        "empty-DB alembic upgrade already executes 028→029."
    )
    alert_id = f"LPA-MIGRATION-{uuid.uuid4().hex[:12]}"
    integration_event_id = f"INT-MIGRATION-{uuid.uuid4().hex[:12]}"
    source_first = datetime(2026, 1, 1, tzinfo=UTC)
    source_last = datetime(2026, 1, 2, tzinfo=UTC)
    received = datetime(2026, 8, 1, tzinfo=UTC)
    with SessionLocal() as db, db.begin():
        db.add(
            PrivacyAlert(
                alert_id=alert_id,
                alert_time=source_first,
                received_at=received,
                source_type="api_log",
                source_format="generic_json",
                severity=Severity.MEDIUM,
                status="new",
                sensitive_types=[],
                masked_values=[],
                detection_ids=[],
                raw_event_hash="sha256:synthetic",
                safety_status="safe",
                alert_summary="safe synthetic migration row",
                first_seen=source_first,
                last_seen=source_last,
                repeat_count=2,
                affected_trace_count=1,
                trace_count_quality="exact",
                alert_findings=[],
                correlation_keys={"trace_id": "legacy-raw-trace"},
            )
        )
        db.flush()
        db.add(
            AlertTraceReference(
                alert_id=alert_id,
                trace_fingerprint="legacy-raw-trace",
                fingerprint_method="hmac_sha256_v1",
                fingerprint_version="v1",
                first_seen=source_first,
                last_seen=source_last,
            )
        )
        db.add(
            IntegrationEvent(
                integration_event_id=integration_event_id,
                schema_version="1",
                source_name="wave2d-test",
                source_tool="wave2d-test",
                source_type="custom",
                source_format="generic_json",
                event_time=source_first,
                received_at=received,
                trace_id="legacy-raw-trace",
                correlation_keys={"trace_id": "legacy-raw-trace"},
                safety_status="safe",
                sensitive_types=[],
                masked_values=[],
                missing_metadata=[],
                recommendations=[],
                source_time_quality="reported_utc",
                source_time_inferred=False,
                source_timezone_name="UTC",
            )
        )

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", str(get_settings().database_url))
    command.stamp(config, "029_alert_correlation_integrity")
    command.downgrade(config, "028_controlled_retest_verification")
    try:
        command.upgrade(config, "029_alert_correlation_integrity")
        with SessionLocal() as db:
            row = db.execute(
                text(
                    "SELECT first_source_event_time, last_source_event_time, first_seen, "
                    "last_seen, affected_trace_count, trace_count_quality, correlation_keys "
                    "FROM privacy_alerts WHERE alert_id = :alert_id"
                ),
                {"alert_id": alert_id},
            ).mappings().one()
            assert row["first_source_event_time"] == source_first
            assert row["last_source_event_time"] == source_last
            assert row["first_seen"] == received
            assert row["last_seen"] == received
            assert row["affected_trace_count"] is None
            assert row["trace_count_quality"] == "unavailable"
            assert "trace_id" not in row["correlation_keys"]
            trace = db.execute(
                text(
                    "SELECT fingerprint_method, fingerprint_version FROM alert_trace_references "
                    "WHERE alert_id = :alert_id"
                ),
                {"alert_id": alert_id},
            ).mappings().one()
            assert trace == {"fingerprint_method": "legacy_untrusted", "fingerprint_version": "legacy"}
            integration = db.execute(
                text(
                    "SELECT trace_id, correlation_keys, source_time_quality, source_time_inferred "
                    "FROM integration_events WHERE integration_event_id = :event_id"
                ),
                {"event_id": integration_event_id},
            ).mappings().one()
            assert integration["trace_id"] is None
            assert "trace_id" not in integration["correlation_keys"]
            assert integration["source_time_quality"] == "legacy_reported"
            assert integration["source_time_inferred"] is False
    finally:
        command.upgrade(config, "head")
