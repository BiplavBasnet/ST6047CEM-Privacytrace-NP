from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from app.database import SessionLocal
from app.models.enums import Severity
from app.models.incident import Incident
from app.models.privacy_alert import PrivacyAlert
from app.services import live_monitor_service

pytestmark = pytest.mark.usefixtures("migrated_db")


def test_concurrent_create_new_claims_alert_once(db_session, monkeypatch):
    alert_id = "PAL-LINK-RACE"
    with SessionLocal() as persist, persist.begin():
        persist.add(
            PrivacyAlert(
                alert_id=alert_id, alert_time=datetime.now(UTC), source_type="api_log",
                source_name="synthetic", source_format="json", severity=Severity.MEDIUM,
                status="new", sensitive_types=[], masked_values=[], detection_ids=[],
                raw_event_hash="sha256:synthetic", alert_summary="Synthetic masked alert",
            )
        )
    monkeypatch.setattr(live_monitor_service, "_ensure_alert_evidence", lambda *a: None)
    monkeypatch.setattr(live_monitor_service.causality_engine, "mark_stale", lambda *a: None)
    monkeypatch.setattr(
        live_monitor_service.privacy_ingestion_pipeline_service,
        "refresh_exposure_profiles", lambda *a, **k: None,
    )
    from app.services import privacy_impact_service
    monkeypatch.setattr(privacy_impact_service, "assess_incident", lambda *a, **k: None)

    def claim():
        with SessionLocal() as session:
            try:
                return live_monitor_service.create_or_link_incident(
                    session, alert_id=alert_id, mode="create_new", incident_id=None,
                    actor_id=None, actor_email=None, actor_role=None,
                ).incident_id
            except live_monitor_service.LiveAlertStateError:
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert len([item for item in results if item]) == 1
    db_session.expire_all()
    linked = db_session.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id))
    assert linked.linked_incident_id in results
    assert db_session.scalar(select(func.count(Incident.id)).where(Incident.incident_id == linked.linked_incident_id)) == 1
