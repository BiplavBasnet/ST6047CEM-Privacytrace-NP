"""Phase 3 tests: sample ingestion, hashing, evidence API."""

import io

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models.enums import EvidenceType, ParsingStatus
from app.services import ingestion_service

SCENARIO_1_FILE_COUNT = 8


def test_compute_file_hash_prefix_and_stable():
    content = b"synthetic test content"
    h1 = ingestion_service.compute_file_hash(content)
    h2 = ingestion_service.compute_file_hash(content)
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_generate_evidence_id_format():
    eid = ingestion_service.generate_evidence_id()
    assert eid.startswith("EVD-")
    assert len(eid) == 16  # EVD- + 12 hex


def test_validate_upload_extension_rejects_unknown():
    with pytest.raises(ValueError, match="Unsupported"):
        ingestion_service.validate_upload_extension("malware.exe")


def test_app_has_evidence_routes():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    assert "/evidence/upload" in paths or any("/evidence" in p for p in paths)
    assert "/incidents/analyse" in paths


@pytest.mark.integration
def test_load_sample_creates_evidence_rows(client: TestClient, seeded_db):
    response = client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    assert response.status_code == 200
    data = response.json()
    assert len(data["loaded"]) == SCENARIO_1_FILE_COUNT
    assert len(data["evidence_ids"]) == SCENARIO_1_FILE_COUNT
    assert "EVD-S1-API-001" in data["evidence_ids"]


@pytest.mark.integration
def test_loaded_evidence_has_hash_and_pending_status(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    listing = client.get("/evidence").json()
    assert len(listing) >= SCENARIO_1_FILE_COUNT
    for row in listing:
        if row["evidence_id"].startswith("EVD-S1-"):
            assert row["file_hash"] is not None
            assert row["file_hash"].startswith("sha256:")
            assert row["parsing_status"] == ParsingStatus.PENDING.value


@pytest.mark.integration
def test_upload_evidence_file(client: TestClient, migrated_db):
    content = b'{"synthetic": true, "endpoint": "/api/v1/wallet/transfer"}'
    response = client.post(
        "/evidence/upload",
        data={
            "evidence_type": EvidenceType.API_LOG.value,
            "source_system": "test-upload",
        },
        files={"file": ("synthetic_upload.json", io.BytesIO(content), "application/json")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["evidence"]["file_hash"].startswith("sha256:")
    assert body["evidence"]["parsing_status"] == ParsingStatus.PENDING.value


@pytest.mark.integration
def test_get_evidence_by_id(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    response = client.get("/evidence/EVD-S1-SAST-001")
    assert response.status_code == 200
    assert response.json()["evidence_type"] == EvidenceType.SEMGREP_REPORT.value


@pytest.mark.integration
def test_load_sample_idempotent_skips_duplicates(client: TestClient, seeded_db):
    first = client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    second = client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    assert first.status_code == 200
    assert second.status_code == 200
    assert len(second.json()["loaded"]) == 0
    assert len(second.json()["skipped"]) == SCENARIO_1_FILE_COUNT


@pytest.mark.integration
def test_upload_rejects_unsupported_extension(client: TestClient, migrated_db):
    response = client.post(
        "/evidence/upload",
        data={"evidence_type": EvidenceType.API_LOG.value},
        files={"file": ("bad.exe", io.BytesIO(b"data"), "application/octet-stream")},
    )
    assert response.status_code == 400


@pytest.mark.integration
def test_health_still_works_phase3(client: TestClient, migrated_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"
