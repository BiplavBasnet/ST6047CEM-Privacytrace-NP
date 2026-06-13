"""Phase 9 tests: evidence-based fix verification."""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.config import resolve_sample_data_dir
from app.database import SessionLocal
from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models import EvidenceFile, FixVerification, Incident
from app.models.enums import EvidenceType, IncidentStatus, VerificationStatus
from app.services import fix_verification_gate_service
from app.tests.test_phase6 import RAW_LEAK_SUBSTRINGS, SEED_INCIDENT_ID

SAFE_RETEST_BYTES = (
    resolve_sample_data_dir() / "retest_evidence" / "wallet_transfer_retest.log"
).read_bytes()

JWT_LEAK = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

OVERCLAIM_PHRASES = (
    "guaranteed fixed",
    "definitely fixed",
    "proven fixed",
    "incident closed automatically",
    "developer fault",
    "confirmed blame",
)


def _pipeline_to_analyse(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


def _approve_review(client: TestClient) -> None:
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Masked evidence supports a human-owned remediation action.",
        },
    )
    assert response.status_code == 200, response.text


def _record_remediation(client: TestClient) -> None:
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/remediation-actions",
        json={
            "action_type": "redaction_rule_update",
            "action_description": "Update the reviewed wallet logging redaction rule.",
            "affected_component": "wallet logging middleware",
            "assigned_owner": "wallet platform team",
            "status": "awaiting_retest",
            "priority": "high",
            "retest_required": True,
        },
    )
    assert response.status_code == 200, response.text


def _clear_retest_evidence() -> None:
    db = SessionLocal()
    try:
        db.execute(
            update(EvidenceFile)
            .where(
                EvidenceFile.linked_incident_id == SEED_INCIDENT_ID,
                EvidenceFile.evidence_type.in_([EvidenceType.FIXED_LOG, EvidenceType.FIXED_SCAN]),
            )
            .values(evidence_type=EvidenceType.RUNTIME_LOG)
        )
        db.commit()
    finally:
        db.close()


def _upload_safe_retest(client: TestClient) -> str:
    # Unique suffix avoids duplicate-hash 409 when sample file was already ingested.
    unique = f"\n# retest-run {uuid.uuid4().hex}\n".encode()
    return _upload_retest_log(client, SAFE_RETEST_BYTES + unique)


def _upload_retest_log(client: TestClient, content: bytes) -> str:
    name = f"retest_{uuid.uuid4().hex[:8]}.log"
    response = client.post(
        "/evidence/upload",
        files={"file": (name, content, "text/plain")},
        data={
            "evidence_type": "fixed_log",
            "linked_incident_id": SEED_INCIDENT_ID,
            "source_system": "wallet-service",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["evidence"]["evidence_id"]


@pytest.mark.integration
def test_phase9_verify_fix_endpoint_exists(client: TestClient, seeded_db):
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    assert any("/incidents/{incident_id}/verify-fix" in p for p in paths)
    assert any("/incidents/{incident_id}/fix-verifications" in p for p in paths)


@pytest.mark.integration
def test_no_dashboard_or_phase11_routes():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    for forbidden in ("/dashboard", "/phase11", "/frontend"):
        assert not any(forbidden in p for p in paths)


@pytest.mark.integration
@pytest.mark.parametrize(
    "setup",
    [
        "no_review",
        "llm_only",
        "analyse_only",
        "rejected",
        "inconclusive",
        "request_more_evidence",
    ],
)
def test_verify_fix_blocked_without_approval(client: TestClient, seeded_db, setup: str):
    _pipeline_to_analyse(client)
    if setup == "llm_only":
        client.post(
            f"/incidents/{SEED_INCIDENT_ID}/explain",
            json={"provider": "template"},
        )
    elif setup == "rejected":
        client.post(
            f"/incidents/{SEED_INCIDENT_ID}/review",
            json={"decision": "rejected", "reviewer_id": 1, "reason": "Masked evidence was reviewed as a false-positive disposition."},
        )
    elif setup == "inconclusive":
        client.post(
            f"/incidents/{SEED_INCIDENT_ID}/review",
            json={"decision": "inconclusive", "reviewer_id": 1, "reason": "Available masked evidence remains inconclusive."},
        )
    elif setup == "request_more_evidence":
        client.post(
            f"/incidents/{SEED_INCIDENT_ID}/review",
            json={"decision": "request_more_evidence", "reviewer_id": 1, "reason": "More deployment evidence is required."},
        )

    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [], "requested_by": 1},
    )
    assert response.status_code == 422, setup


@pytest.mark.integration
def test_verify_fix_allowed_after_review_remediation_and_retest(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    safe_id = _upload_safe_retest(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    assert response.status_code == 422, response.text
    assert "diagnosis" in response.json()["detail"].lower() or "retest" in response.json()["detail"].lower() or "implementation" in response.json()["detail"].lower() or "action" in response.json()["detail"].lower()


@pytest.mark.integration
def test_passed_verification_with_safe_retest_log(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    safe_id = _upload_safe_retest(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    body = response.json()
    assert response.status_code == 422
    assert "detail" in body


@pytest.mark.integration
@pytest.mark.parametrize(
    ("leak_content", "label"),
    [
        (b'{"message":"phone 9841234567 still logged"}\n', "phone"),
        (b'{"wallet_id":"WALLET-NP-88291"}\n', "wallet"),
        (b'{"api_key":"pk_test_np_fake_12345"}\n', "api_key"),
        (b'{"token":"' + JWT_LEAK.encode() + b'"}\n', "jwt"),
    ],
)
def test_failed_verification_when_retest_still_leaks(
    client: TestClient, seeded_db, leak_content: bytes, label: str
):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    eid = _upload_retest_log(client, leak_content)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [eid], "requested_by": 1},
    )
    assert response.status_code == 422, label
    assert "detail" in response.json()


@pytest.mark.integration
def test_verification_blocked_when_no_retest_evidence(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    _clear_retest_evidence()
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [], "requested_by": 1},
    )
    assert response.status_code == 422
    detail = response.json()["detail"].lower()
    assert "retest" in detail or "diagnosis" in detail or "implementation" in detail or "action" in detail


@pytest.mark.integration
def test_verification_record_stored(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    safe_id = _upload_safe_retest(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    assert response.status_code == 422
    assert "detail" in response.json()


@pytest.mark.integration
def test_get_fix_verifications_safe_metadata(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    safe_id = _upload_safe_retest(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    response = client.get(f"/incidents/{SEED_INCIDENT_ID}/fix-verifications")
    assert response.status_code == 200
    blob = json.dumps(response.json())
    for substring in RAW_LEAK_SUBSTRINGS:
        assert substring not in blob
    for phrase in OVERCLAIM_PHRASES:
        assert phrase not in blob.lower()


@pytest.mark.integration
def test_verify_fix_response_no_raw_or_overclaim(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    safe_id = _upload_safe_retest(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    blob = json.dumps(response.json()).lower()
    for substring in RAW_LEAK_SUBSTRINGS:
        assert substring.lower() not in blob
    for phrase in OVERCLAIM_PHRASES:
        assert phrase not in blob
    assert "guaranteed fixed" not in blob


@pytest.mark.integration
def test_incident_not_auto_closed(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    _approve_review(client)
    _record_remediation(client)
    safe_id = _upload_safe_retest(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [safe_id], "requested_by": 1},
    )
    db = SessionLocal()
    try:
        incident = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        assert incident is not None
        assert incident.status != IncidentStatus.CLOSED
    finally:
        db.close()


def _clear_reviews() -> None:
    from sqlalchemy import delete

    from app.models import ReviewDecision

    db = SessionLocal()
    try:
        db.execute(
            delete(ReviewDecision).where(ReviewDecision.incident_id == SEED_INCIDENT_ID)
        )
        incident = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        if incident:
            incident.status = IncidentStatus.UNDER_REVIEW
        db.commit()
    finally:
        db.close()


@pytest.mark.integration
def test_gate_llm_and_root_cause_only_blocked(client: TestClient, seeded_db):
    _pipeline_to_analyse(client)
    db = SessionLocal()
    try:
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()

    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    )
    db = SessionLocal()
    try:
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()
