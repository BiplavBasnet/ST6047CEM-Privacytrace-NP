"""Phase 4 tests: evidence normalisation and parse API."""

from __future__ import annotations

import io
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.models.enums import EvidenceType, ParsingStatus
from app.parsers.base import build_event_id, parse_iso_timestamp
from app.parsers.log_parser import parse_log_file
from app.parsers.registry import get_parser
from app.services import normalization_service

SCENARIO_1_MIN_EVENTS = 14


def test_parse_iso_timestamp_zulu():
    dt = parse_iso_timestamp("2026-05-10T08:22:14.331Z")
    assert dt.tzinfo is not None
    assert dt.year == 2026
    assert dt.month == 5


def test_parse_iso_timestamp_invalid():
    with pytest.raises(ValueError):
        parse_iso_timestamp("not-a-date")


def test_build_event_id_format():
    e1 = build_event_id("EVD-S1-API-001", 1)
    e2 = build_event_id("EVD-S1-API-001", 2)
    assert e1 == "EVT-EVD-S1-API-001-001"
    assert e2 != e1


def test_log_parser_ndjson_in_memory():
    content = (
        '{"timestamp":"2026-05-10T08:00:00.000Z","source_type":"api_log",'
        '"service_name":"wallet-service","endpoint":"/api/v1/test",'
        '"event_type":"test","message":"hello","severity":"high"}\n'
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        events = parse_log_file(
            tmp_path,
            evidence_id="EVD-TEST-001",
            evidence_type=EvidenceType.API_LOG,
            linked_incident_id=None,
        )
        assert len(events) == 1
        assert events[0].service_name == "wallet-service"
        assert events[0].endpoint == "/api/v1/test"
    finally:
        tmp_path.unlink(missing_ok=True)


def test_registry_rejects_siem_alert():
    with pytest.raises(ValueError, match="not implemented"):
        get_parser(EvidenceType.SIEM_ALERT)


@pytest.mark.integration
def test_parse_all_scenario1_creates_events(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    response = client.post("/evidence/parse-all")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] >= SCENARIO_1_MIN_EVENTS

    listing = client.get("/evidence").json()
    for row in listing:
        if row["evidence_id"].startswith("EVD-S1-"):
            assert row["parsing_status"] == ParsingStatus.PARSED.value


@pytest.mark.integration
def test_api_log_events_have_service_and_endpoint(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")

    events = client.get("/evidence/EVD-S1-API-001/events").json()
    assert len(events) >= 3
    assert all(e["service_name"] == "wallet-service" for e in events)
    assert any(e["endpoint"] == "/api/v1/wallet/transfer" for e in events)
    for e in events:
        assert e["timestamp"] is not None


@pytest.mark.integration
def test_semgrep_events_have_raw_reference(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")

    events = client.get("/evidence/EVD-S1-SAST-001/events").json()
    assert len(events) >= 1
    assert events[0]["raw_reference"] is not None
    assert "rule:" in events[0]["raw_reference"]


@pytest.mark.integration
def test_unsupported_type_parse_fails_gracefully(client: TestClient, seeded_db):
    payload = json.dumps({"timestamp": "2026-05-10T08:00:00.000Z", "message": "alert"})
    response = client.post(
        "/evidence/upload",
        data={"evidence_type": EvidenceType.SIEM_ALERT.value},
        files={"file": ("siem.json", io.BytesIO(payload.encode()), "application/json")},
    )
    assert response.status_code == 201
    eid = response.json()["evidence"]["evidence_id"]

    parse_resp = client.post(f"/evidence/{eid}/parse")
    assert parse_resp.status_code == 422

    record = client.get(f"/evidence/{eid}").json()
    assert record["parsing_status"] == ParsingStatus.FAILED.value


@pytest.mark.integration
def test_parse_idempotent_then_force(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")

    first = client.post("/evidence/EVD-S1-API-001/parse")
    assert first.status_code == 200
    assert first.json()["skipped"] is True

    events_before = len(client.get("/evidence/EVD-S1-API-001/events").json())

    second = client.post("/evidence/EVD-S1-API-001/parse?force=true")
    assert second.status_code == 200
    assert second.json()["skipped"] is False
    assert second.json()["event_count"] == events_before

    events_after = client.get("/evidence/EVD-S1-API-001/events").json()
    assert len(events_after) == events_before


@pytest.mark.integration
def test_health_still_works_phase4(client: TestClient, seeded_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"
