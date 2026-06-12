from datetime import datetime, timedelta, timezone

from app.services.incident_timeline_service import sort_events, timeline_event


def test_timeline_sorts_by_observed_then_recorded_time():
    base = datetime(2026, 7, 17, 8, 0, tzinfo=timezone.utc)
    later = timeline_event(
        event_id="later",
        incident_id="INC-1",
        event_type="alert_created",
        stage="overview",
        event_timestamp=base + timedelta(minutes=2),
        recorded_timestamp=base + timedelta(minutes=2),
        source_type="breach_alert",
        source_id="BAL-1",
        summary="Internal alert created.",
    )
    earlier = timeline_event(
        event_id="earlier",
        incident_id="INC-1",
        event_type="source_event",
        stage="overview",
        event_timestamp=base,
        recorded_timestamp=base + timedelta(minutes=10),
        source_type="normalized_event",
        source_id="EVT-1",
        summary="Source event observed.",
    )
    ordered = sort_events([later, earlier])
    assert [item.id for item in ordered] == ["earlier", "later"]
    assert earlier.time_status == "delayed_ingestion"
    assert earlier.integrity_status == "not_yet_verified"

