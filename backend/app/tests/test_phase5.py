"""Phase 5 tests: sensitive data detection and masking."""

from __future__ import annotations

import io
import json
import re

import pytest
from fastapi.testclient import TestClient

from app.models.enums import ParsingStatus
from app.services import detection_service, masking_service
from app.services.detection_service import load_sensitive_rules
from app.services.masking_service import MatchSpan

RAW_LEAK_SUBSTRINGS = (
    "9841234567",
    "WALLET-NP-88291",
    "SYNTHETIC_FAKE_PAYLOAD.NOT_A_REAL_TOKEN",
    "pk_test_np_fake_12345",
)


def test_rule_nepal_phone_matches():
    rules = load_sensitive_rules()
    phone_rule = next(r for r in rules if r.sensitive_type == "nepal_phone")
    assert phone_rule.pattern.search("recipient_phone\":\"9841234567")


def test_rule_wallet_matches():
    rules = load_sensitive_rules()
    rule = next(r for r in rules if r.sensitive_type == "wallet_id")
    assert rule.pattern.search("WALLET-NP-88291")


def test_rule_transaction_ref_matches():
    rules = load_sensitive_rules()
    rule = next(r for r in rules if r.sensitive_type == "transaction_ref")
    assert rule.pattern.search("TXN-NP-2026-77881")


def test_rule_jwt_matches():
    rules = load_sensitive_rules()
    rule = next(r for r in rules if r.sensitive_type == "jwt_token")
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "SYNTHETIC_FAKE_PAYLOAD.NOT_A_REAL_TOKEN"
    )
    assert rule.pattern.search(token)


def test_rule_api_key_matches():
    rules = load_sensitive_rules()
    rule = next(r for r in rules if r.sensitive_type == "api_key")
    assert rule.pattern.search("pk_test_np_fake_12345")




def test_rule_access_token_matches():
    rules = load_sensitive_rules()
    rule = next(r for r in rules if r.sensitive_type == "access_token")
    assert rule.pattern.search(r'accessToken":"opaque-access-token-123456')

def test_rule_hyphen_api_key_matches():
    rules = load_sensitive_rules()
    rule = next(r for r in rules if r.sensitive_type == "api_key")
    assert rule.pattern.search("sk-abcdefghijklmnopqrstuvwxyz123456")


def test_rule_password_and_credential_json_matches():
    rules = load_sensitive_rules()
    sample = r'DeviceConfig="{\"mqtt\":{\"name\":\"sptmqtadmin\",\"password\":\"supersecret\"}}"'
    matched_types = {
        rule.sensitive_type
        for rule in rules
        if rule.pattern.search(sample)
    }
    assert "password" in matched_types
    assert "credential_username" in matched_types


def test_mask_text_removes_credential_fields():
    line = r'DeviceConfig="{\"mqtt\":{\"name\":\"sptmqtadmin\",\"password\":\"supersecret\"}}" api_key=sk-abcdefghijklmnopqrstuvwxyz123456'
    rules = load_sensitive_rules()
    matches: list[MatchSpan] = []
    for rule in rules:
        for m in rule.pattern.finditer(line):
            matches.append(
                MatchSpan(
                    start=m.start(),
                    end=m.end(),
                    sensitive_type=rule.sensitive_type,
                    raw_value=m.group(0),
                )
            )
    masked = masking_service.mask_text(line, matches)
    assert "supersecret" not in masked
    assert "sptmqtadmin" not in masked
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in masked
    assert "password_[masked]" in masked
    assert "key_[masked]" in masked

def test_mask_value_phone_format():
    masked = masking_service.mask_value("nepal_phone", "9841234567")
    assert masked == "98******67"


def test_mask_value_wallet_format():
    masked = masking_service.mask_value("wallet_id", "WALLET-NP-88291")
    assert masked == "wallet_[masked]"


def test_mask_value_jwt_format():
    masked = masking_service.mask_value("jwt_token", "eyJabc.def.ghi")
    assert masked == "jwt_[masked]"


def test_mask_text_removes_raw_substrings():
    line = (
        'TransferHandler wallet=WALLET-NP-88291 phone=9841234567 '
        "txn=TXN-NP-2026-77881"
    )
    rules = load_sensitive_rules()
    matches: list[MatchSpan] = []
    for rule in rules:
        for m in rule.pattern.finditer(line):
            matches.append(
                MatchSpan(
                    start=m.start(),
                    end=m.end(),
                    sensitive_type=rule.sensitive_type,
                    raw_value=m.group(0),
                )
            )
    masked = masking_service.mask_text(line, matches)
    for raw in ("9841234567", "WALLET-NP-88291", "TXN-NP-2026-77881"):
        assert raw not in masked


def test_hash_raw_value_stable_prefix():
    h1 = detection_service.hash_raw_value("9841234567")
    h2 = detection_service.hash_raw_value("9841234567")
    assert h1 == h2
    assert h1.startswith("sha256:")


@pytest.mark.integration
def test_detect_all_scenario1(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    response = client.post("/evidence/detect-all")
    assert response.status_code == 200
    data = response.json()
    assert data["total_detections"] > 0


@pytest.mark.integration
def test_api_log_detections_count(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")

    detections = client.get("/evidence/EVD-S1-API-001/detections").json()
    types = {d["sensitive_type"] for d in detections}
    assert len(detections) >= 3
    # Canonical taxonomy names from the unified exposure engine (see
    # `sensitive_data_taxonomy_service`), not the legacy regex-rule names.
    assert "phone_number" in types
    assert "wallet_identifier" in types
    assert "transaction_reference" in types


@pytest.mark.integration
def test_no_raw_leak_in_api_responses(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")

    events = client.get("/evidence/EVD-S1-API-001/events").json()
    detections = client.get("/evidence/EVD-S1-API-001/detections").json()
    payload = json.dumps({"events": events, "detections": detections})

    for raw in RAW_LEAK_SUBSTRINGS:
        assert raw not in payload

    for det in detections:
        assert "raw_value_hash" not in det


@pytest.mark.integration
def test_events_masked_message_patterns(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")

    events = client.get("/evidence/EVD-S1-API-001/events").json()
    messages = " ".join(e["masked_message"] or "" for e in events)
    assert re.search(r"\*+", messages) or "[masked]" in messages


@pytest.mark.integration
def test_detect_idempotent_then_force(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")

    first = client.post("/evidence/EVD-S1-API-001/detect")
    assert first.status_code == 200
    assert first.json()["skipped"] is True

    count_before = len(client.get("/evidence/EVD-S1-API-001/detections").json())

    second = client.post("/evidence/EVD-S1-API-001/detect?force=true")
    assert second.status_code == 200
    assert second.json()["skipped"] is False

    count_after = len(client.get("/evidence/EVD-S1-API-001/detections").json())
    assert count_after == count_before


@pytest.mark.integration
def test_detect_unparsed_evidence_returns_422(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    payload = json.dumps({"timestamp": "2026-05-10T08:00:00.000Z", "message": "pending"})
    upload = client.post(
        "/evidence/upload",
        data={"evidence_type": "api_log"},
        files={"file": ("pending.log", io.BytesIO(payload.encode()), "text/plain")},
    )
    assert upload.status_code == 201
    evidence_id = upload.json()["evidence"]["evidence_id"]
    assert upload.json()["evidence"]["parsing_status"] == ParsingStatus.PENDING.value

    response = client.post(f"/evidence/{evidence_id}/detect")
    assert response.status_code == 422


@pytest.mark.integration
def test_health_still_works_phase5(client: TestClient, seeded_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"
