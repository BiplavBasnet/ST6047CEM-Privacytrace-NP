"""Phase 8 tests: human review decisions and audit trail."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models import AuditLog, Incident, ReviewDecision
from app.models.enums import IncidentStatus
from app.services import audit_service, review_service
from app.tests.test_phase6 import RAW_LEAK_SUBSTRINGS, SEED_INCIDENT_ID


def _run_pipeline_to_analyse(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


def test_parse_decision_aliases():
    from app.models.enums import ReviewDecisionType

    assert review_service.parse_decision("approve") == ReviewDecisionType.APPROVED
    assert review_service.parse_decision("reject") == ReviewDecisionType.REJECTED
    assert (
        review_service.parse_decision("request_more_evidence")
        == ReviewDecisionType.REQUEST_MORE_EVIDENCE
    )


def test_parse_decision_invalid():
    with pytest.raises(review_service.InvalidDecisionError):
        review_service.parse_decision("maybe")


@pytest.mark.integration
def test_review_before_analyse_returns_422(client: TestClient, seeded_db):
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Available masked evidence has not been analysed yet.",
        },
    )
    assert response.status_code == 422
    assert "analysed" in response.json()["detail"].lower()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("decision", "expected_status"),
    [
        ("approved", IncidentStatus.CONFIRMED_INCIDENT.value),
        ("rejected", IncidentStatus.FALSE_POSITIVE.value),
        ("inconclusive", IncidentStatus.UNDER_REVIEW.value),
        ("request_more_evidence", IncidentStatus.NEEDS_MORE_EVIDENCE.value),
    ],
)
def test_review_updates_incident_status(
    client: TestClient,
    seeded_db,
    decision: str,
    expected_status: str,
):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": decision,
            "reviewer_id": 1,
            "reason": f"Masked evidence was reviewed for decision {decision}.",
            "comment": f"Phase 8 test decision: {decision}",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["incident_status"] == expected_status
    assert body["review"]["decision"] == decision
    assert body["audit_log_id"] > 0

    db = SessionLocal()
    try:
        incident = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        assert incident is not None
        assert incident.status.value == expected_status
    finally:
        db.close()


@pytest.mark.integration
def test_review_stored_and_audit_log_created(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Masked API log evidence supports the ranked likely cause.",
            "comment": "Likely cause aligns with masked API log evidence.",
        },
    )
    assert response.status_code == 200
    review_id = response.json()["review"]["id"]
    audit_log_id = response.json()["audit_log_id"]

    db = SessionLocal()
    try:
        review = db.get(ReviewDecision, review_id)
        assert review is not None
        assert review.incident_id == SEED_INCIDENT_ID
        assert review.decision == "approved"

        audit = db.get(AuditLog, audit_log_id)
        assert audit is not None
        assert audit.action == "review_submitted"
        assert audit.target_id == SEED_INCIDENT_ID
        details = audit_service.resolve_audit_details(audit)
        assert details["decision"] == "approved"
    finally:
        db.close()


@pytest.mark.integration
def test_list_reviews_and_audit_logs(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "inconclusive",
            "reviewer_id": 1,
            "reason": "Available masked evidence remains inconclusive.",
        },
    )

    reviews_resp = client.get(f"/incidents/{SEED_INCIDENT_ID}/reviews")
    assert reviews_resp.status_code == 200
    reviews_body = reviews_resp.json()
    assert reviews_body["total"] >= 1
    assert reviews_body["reviews"][0]["decision"] == "inconclusive"

    audit_resp = client.get(
        "/audit-logs",
        params={"incident_id": SEED_INCIDENT_ID, "action": "review_submitted"},
    )
    assert audit_resp.status_code == 200
    logs = audit_resp.json()["logs"]
    assert len(logs) >= 1
    assert logs[0]["action"] == "review_submitted"


@pytest.mark.integration
def test_review_audit_details_no_raw_leaks(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Masked evidence was reviewed without retaining raw values.",
        },
    )
    audit_resp = client.get("/audit-logs", params={"incident_id": SEED_INCIDENT_ID})
    blob = json.dumps(audit_resp.json())
    for substring in RAW_LEAK_SUBSTRINGS:
        assert substring not in blob


@pytest.mark.integration
def test_phase9_verify_fix_route_registered():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    assert any("/verify-fix" in p for p in paths)
