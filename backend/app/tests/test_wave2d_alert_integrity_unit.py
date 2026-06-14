from datetime import UTC, datetime, timedelta

from app.models.enums import Severity
from app.models.privacy_alert import PrivacyAlert
from app.schemas.live_monitor_schema import LiveMonitorEventRequest
from app.services import (
    correlation_fingerprint_service,
    live_alert_grouping_service,
    live_monitor_service,
)


def test_policy_identifiers_are_hmac_versioned_and_never_returned_raw():
    raw = "trace-synthetic-001"
    first = correlation_fingerprint_service.fingerprint_keys({"trace_id": raw})
    second = correlation_fingerprint_service.fingerprint_keys({"trace_id": raw})
    assert first == second
    assert first["trace_id_fingerprint"].startswith("HMAC-SHA256-V1:")
    assert first["fingerprint_method"] == "hmac_sha256_v1"
    assert raw not in str(first)


def test_live_extraction_fingerprints_all_designated_ids():
    event = LiveMonitorEventRequest(
        message="safe synthetic event",
        trace_id="trace-1",
        request_id="request-1",
        correlation_id="correlation-1",
        metadata={"transaction_id": "txn-1", "session_id": "session-1"},
    )
    keys = live_monitor_service.extract_correlation_keys(event)
    assert set(keys) >= {
        "trace_id_fingerprint",
        "request_id_fingerprint",
        "correlation_id_fingerprint",
        "transaction_reference_fingerprint",
        "session_reference_fingerprint",
        "fingerprint_method",
        "fingerprint_version",
    }
    assert not ({"trace_id", "request_id", "correlation_id"} & set(keys))
    assert not any(raw in str(keys) for raw in ("trace-1", "request-1", "txn-1", "session-1"))


def test_recurrence_uses_ingestion_time_and_keeps_source_time_separate(monkeypatch):
    source_first = datetime(2026, 1, 1, tzinfo=UTC)
    received_first = datetime(2026, 8, 1, tzinfo=UTC)
    alert = PrivacyAlert(
        alert_id="LPA-SYNTHETIC",
        alert_time=source_first,
        received_at=received_first,
        source_type="api_log",
        source_format="generic_json",
        severity=Severity.MEDIUM,
        status="new",
        sensitive_types=[],
        masked_values=[],
        detection_ids=[],
        raw_event_hash="sha256:test",
        safety_status="safe",
        alert_summary="safe",
        first_seen=received_first,
        last_seen=received_first,
        repeat_count=1,
        first_source_event_time=source_first,
        last_source_event_time=source_first,
        alert_findings=[],
    )
    monkeypatch.setattr(live_alert_grouping_service, "record_trace_reference", lambda *a, **k: alert)
    delayed_source = source_first - timedelta(days=1)
    received_next = received_first + timedelta(minutes=1)
    live_alert_grouping_service.register_recurrence(
        object(), alert, observed_at=received_next, source_event_time=delayed_source
    )
    assert alert.last_seen == received_next
    assert alert.first_source_event_time == delayed_source
    assert alert.last_source_event_time == source_first
    assert alert.repeat_count == 2


def test_naive_source_timestamp_is_explicitly_assumed_utc():
    naive = datetime(2026, 8, 13, 10, 0)
    assert live_monitor_service._utc(naive) == naive.replace(tzinfo=UTC)
