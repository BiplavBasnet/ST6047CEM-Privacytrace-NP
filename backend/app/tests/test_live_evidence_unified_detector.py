"""Phase H: unified detection — same value classified consistently regardless
of whether it is observed through the Evidence upload path
(`detection_service.detect_event`) or the Live Monitor path
(`live_monitor_service.process_event`).

Both paths now run the same `sensitive_exposure_engine.analyse` pipeline (see
docs/CORE_ENGINE_BASELINE_AUDIT.md), so a value seen through either channel
with the same source_type/service/endpoint should be assigned the same
canonical taxonomy type, the same masked preview, and the same confidence
score — instead of each path having its own regex list and a hardcoded
confidence value.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.dependencies import get_db_session
from app.main import app
from app.models.enums import EvidenceType, IncidentStatus, ParsingStatus, Severity
from app.models.evidence_file import EvidenceFile
from app.models.incident import Incident
from app.models.normalized_event import NormalizedEvent
from app.models.privacy_alert import PrivacyAlert
from app.services import detection_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

RAW_PHONE = "9841234567"
MASKED_PHONE = "98******67"
INCIDENT_ID = "INC-UNIFIED-DETECTOR-001"
EVIDENCE_ID = "EVD-UNIFIED-DETECTOR-001"
EVENT_ID = "EVT-UNIFIED-DETECTOR-001"


@pytest.fixture(autouse=True)
def override_db_session(db_session):
    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _analyst_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client_no_auth_override, email="analyst@privacytrace.local", password="AnalystPass123!"
    )


def _seed_evidence_event(db_session) -> NormalizedEvent:
    incident = Incident(
        incident_id=INCIDENT_ID,
        title="Synthetic phone number appears in application log",
        affected_service="wallet-service",
        affected_endpoint="/wallet/transfer",
        status=IncidentStatus.NEW,
        severity=Severity.HIGH,
        first_seen=datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc),
        summary="Synthetic evidence for the unified detector test.",
    )
    evidence = EvidenceFile(
        evidence_id=EVIDENCE_ID,
        file_name="unified_detector.log",
        evidence_type=EvidenceType.API_LOG,
        source_system="wallet-service",
        file_hash="sha256:" + ("b" * 64),
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=INCIDENT_ID,
    )
    event = NormalizedEvent(
        event_id=EVENT_ID,
        evidence_id=evidence.evidence_id,
        timestamp=datetime(2026, 5, 20, 10, 1, tzinfo=timezone.utc),
        source_type="api_log",
        service_name="wallet-service",
        endpoint="/wallet/transfer",
        event_type="http_request",
        raw_reference="unified-detector-test",
        masked_message=f"Synthetic phone {RAW_PHONE} copied into log",
        severity=Severity.HIGH,
        linked_incident_id=INCIDENT_ID,
    )
    db_session.add_all([incident, evidence, event])
    db_session.flush()
    return event


def test_same_phone_number_classified_consistently_live_vs_evidence(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)

    # Evidence path.
    event = _seed_evidence_event(db_session)
    detections = detection_service.detect_event(db_session, event, incident_id=INCIDENT_ID)
    db_session.flush()
    assert len(detections) == 1
    evidence_detection = detections[0]
    assert evidence_detection.sensitive_type == "phone_number"
    assert evidence_detection.masked_value == MASKED_PHONE
    assert evidence_detection.confidence is not None
    assert evidence_detection.confidence > 0
    assert evidence_detection.severity == Severity.HIGH
    assert RAW_PHONE not in (event.masked_message or "")

    # Live Monitor path: same value, same source_type/service/endpoint.
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={
            "source_type": "api_log",
            "source_name": "wallet-service",
            "source_format": "generic_json",
            "service_name": "wallet-service",
            "endpoint": "/wallet/transfer",
            "environment": "demo",
            "timestamp": "2026-05-20T10:15:00Z",
            "message": f"Synthetic phone {RAW_PHONE} copied into log",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "alert_created"
    assert body["sensitive_types"] == ["phone_number"]
    assert body["masked_values"] == [MASKED_PHONE]
    assert RAW_PHONE not in response.text

    alert = db_session.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == body["alert_id"]))
    assert alert is not None

    # Same underlying value + same channel context -> the two independent
    # ingestion paths must agree on taxonomy type, masked preview, and
    # confidence score instead of drifting (e.g. a hardcoded 0.92 on one
    # side and an engine-computed score on the other).
    assert alert.sensitive_types == [evidence_detection.sensitive_type]
    assert alert.masked_values == [evidence_detection.masked_value]
    assert alert.confidence_score == pytest.approx(evidence_detection.confidence, abs=1e-6)


def test_evidence_path_never_hardcodes_the_legacy_confidence_value(db_session):
    """`detect_event` must use the engine's computed confidence, not the
    formerly hardcoded 0.92 used for every live-monitor-created Detection."""

    event = _seed_evidence_event(db_session)
    detections = detection_service.detect_event(db_session, event, incident_id=INCIDENT_ID)
    assert len(detections) == 1
    assert detections[0].detector_name != "regex_v1"


def test_evidence_path_uses_hmac_fingerprint_when_available(db_session):
    event = _seed_evidence_event(db_session)
    detections = detection_service.detect_event(db_session, event, incident_id=INCIDENT_ID)
    assert len(detections) == 1
    raw_value_hash = detections[0].raw_value_hash
    assert raw_value_hash is not None
    # HMAC only — unkeyed sha256: fallback was removed (AA hardening).
    assert raw_value_hash.startswith("HMAC-SHA256-V1:")
    assert not raw_value_hash.startswith("sha256:")
