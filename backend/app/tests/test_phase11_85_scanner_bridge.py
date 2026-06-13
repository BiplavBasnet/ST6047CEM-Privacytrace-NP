"""Phase 11.85 ScannerBridge-NP integration tests."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.seed_phase2 import seed_phase2
from app.models.audit_log import AuditLog
from app.models.evidence_file import EvidenceFile
from app.models.enums import EvidenceType
from app.models.scanner_evidence_record import ScannerEvidenceRecord
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db")

SAMPLES = Path(__file__).resolve().parents[1] / "sample_data" / "scanner_outputs"

FORMAT_FILES = {
    "generic_secret_scanner_json": "generic_secret_scanner_sample.json",
    "external_secret_scanner_json": "external_secret_scanner_sample.json",
    "gitleaks_json": "gitleaks_sample.json",
    "semgrep_sarif": "semgrep_sarif_sample.json",
    "semgrep_json": "semgrep_json_sample.json",
}


@pytest.fixture(autouse=True)
def override_db_session_for_scanner_api(db_session):
    from app.dependencies import get_db_session
    from app.main import app

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
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def seeded_incident(db_session):
    seed_phase2(db_session)
    db_session.commit()
    yield "INC-SEED-001"


def _admin_token(client, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )


def _viewer_token(client, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client,
        email="viewer@privacytrace.local",
        password="ViewerPass123!",
    )


def _load_sample(fmt: str) -> dict | list:
    path = SAMPLES / FORMAT_FILES[fmt]
    return json.loads(path.read_text(encoding="utf-8"))


def test_scanner_bridge_routes_registered(client_no_auth_override):
    response = client_no_auth_override.post(
        "/scanner-bridge/preview",
        json={"source_format": "gitleaks_json", "payload": []},
    )
    assert response.status_code in (401, 403, 422)


def test_preview_requires_auth(client_no_auth_override):
    payload = _load_sample("gitleaks_json")
    response = client_no_auth_override.post(
        "/scanner-bridge/preview",
        json={"source_format": "gitleaks_json", "payload": payload},
    )
    assert response.status_code == 401


def test_viewer_cannot_import(
    client_no_auth_override, demo_users, db_session
):
    token = _viewer_token(client_no_auth_override, demo_users, db_session)
    payload = _load_sample("gitleaks_json")
    response = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={
            "source_format": "gitleaks_json",
            "payload": payload,
            "linked_incident_id": "INC-SEED-001",
        },
    )
    assert response.status_code == 403


@pytest.mark.parametrize("source_format", list(FORMAT_FILES.keys()))
def test_preview_all_formats(
    client_no_auth_override, demo_users, db_session, source_format
):
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    payload = _load_sample(source_format)
    response = client_no_auth_override.post(
        "/scanner-bridge/preview",
        headers=auth_headers(token),
        json={"source_format": source_format, "payload": payload},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detected_format"] == source_format
    assert body["import_allowed"] is True
    assert len(body["safe_preview_findings"]) >= 1
    assert "raw_payload" not in json.dumps(body).lower()


@pytest.mark.parametrize("source_format", list(FORMAT_FILES.keys()))
def test_import_all_formats(
    client_no_auth_override,
    demo_users,
    db_session,
    seeded_incident,
    source_format,
):
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    payload = _load_sample(source_format)
    response = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={
            "source_format": source_format,
            "payload": payload,
            "linked_incident_id": seeded_incident,
            "service_hint": "wallet-service",
            "endpoint_hint": "/api/v1/wallet/transfer",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["imported_count"] >= 1
    assert body["import_evidence_id"]
    assert body["scanner_evidence_ids"]

    evidence = db_session.scalar(
        select(EvidenceFile).where(EvidenceFile.evidence_id == body["import_evidence_id"])
    )
    assert evidence is not None
    assert evidence.evidence_type == EvidenceType.SCANNER_BRIDGE_IMPORT

    record = db_session.scalar(
        select(ScannerEvidenceRecord).where(
            ScannerEvidenceRecord.scanner_evidence_id == body["scanner_evidence_ids"][0]
        )
    )
    assert record is not None
    assert record.raw_payload_hash
    assert record.linked_incident_id == seeded_incident


def test_import_link_correlate_flow(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    payload = _load_sample("gitleaks_json")
    import_resp = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={
            "source_format": "gitleaks_json",
            "payload": payload,
        },
    )
    assert import_resp.status_code == 200
    scanner_id = import_resp.json()["scanner_evidence_ids"][0]

    link_resp = client_no_auth_override.post(
        f"/scanner-bridge/evidence/{scanner_id}/link",
        headers=auth_headers(token),
        json={"incident_id": seeded_incident},
    )
    assert link_resp.status_code == 200
    assert link_resp.json()["linked_incident_id"] == seeded_incident

    list_resp = client_no_auth_override.get(
        f"/scanner-bridge/incidents/{seeded_incident}/scanner-evidence",
        headers=auth_headers(token),
    )
    assert list_resp.status_code == 200
    assert any(r["scanner_evidence_id"] == scanner_id for r in list_resp.json())

    corr_resp = client_no_auth_override.post(
        f"/scanner-bridge/incidents/{seeded_incident}/correlate",
        headers=auth_headers(token),
    )
    assert corr_resp.status_code == 200
    corr = corr_resp.json()
    assert corr["human_review_required"] is True
    assert corr["incident_id"] == seeded_incident
    assert "supporting evidence" in corr["summary"].lower()


def test_duplicate_import_skips_findings(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    payload = _load_sample("generic_secret_scanner_json")
    body = {
        "source_format": "generic_secret_scanner_json",
        "payload": payload,
        "linked_incident_id": seeded_incident,
    }
    first = client_no_auth_override.post(
        "/scanner-bridge/import", headers=auth_headers(token), json=body
    )
    second = client_no_auth_override.post(
        "/scanner-bridge/import", headers=auth_headers(token), json=body
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["imported_count"] == 0
    assert any("duplicate" in w for w in second.json().get("safety_warnings", []))


def test_import_audit_logged(
    client_no_auth_override, demo_users, db_session, seeded_incident
):
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    payload = _load_sample("semgrep_json")
    response = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={
            "source_format": "semgrep_json",
            "payload": payload,
            "linked_incident_id": seeded_incident,
        },
    )
    assert response.status_code == 200
    import_id = response.json()["import_evidence_id"]
    db_session.commit()
    rows = db_session.scalars(
        select(AuditLog).where(AuditLog.action == "scanner_bridge_import")
    ).all()
    assert any(r.target_id == import_id for r in rows)


def test_scanner_upload_rejects_oversized_payload(
    client_no_auth_override, demo_users, db_session, monkeypatch
):
    from app.config import get_settings

    monkeypatch.setenv("MAX_UPLOAD_BYTES", "32")
    get_settings.cache_clear()
    token = _admin_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/scanner-bridge/preview/upload",
        headers=auth_headers(token),
        data={"source_format": "gitleaks_json"},
        files={"file": ("scanner.json", io.BytesIO(b"x" * 64), "application/json")},
    )
    get_settings.cache_clear()
    assert response.status_code == 413
    assert "x" * 16 not in response.text
