"""Phase 8 hardening: review policy, audit safety, fix-verification gate."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database import SessionLocal
from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models import AuditLog, Incident, LlmReport, ReviewDecision
from app.models.enums import IncidentStatus, ReviewDecisionType
from app.services import (
    audit_safety_service,
    fix_verification_gate_service,
    review_policy_service,
)
from app.tests.test_phase6 import RAW_LEAK_SUBSTRINGS, SEED_INCIDENT_ID


def _run_pipeline_to_analyse(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


# --- Risk 1: review policy mapping ---


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        (ReviewDecisionType.APPROVED, IncidentStatus.CONFIRMED_INCIDENT),
        (ReviewDecisionType.REJECTED, IncidentStatus.FALSE_POSITIVE),
        (ReviewDecisionType.INCONCLUSIVE, IncidentStatus.UNDER_REVIEW),
        (ReviewDecisionType.REQUEST_MORE_EVIDENCE, IncidentStatus.NEEDS_MORE_EVIDENCE),
    ],
)
def test_map_review_decision_to_status(decision, expected):
    assert review_policy_service.map_review_decision_to_status(decision) == expected


def test_invalid_review_decision_rejected_by_policy():
    with pytest.raises(review_policy_service.InvalidReviewDecisionError):
        review_policy_service.parse_review_decision("maybe")


@pytest.mark.integration
def test_invalid_decision_does_not_update_status_or_audit(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)

    db = SessionLocal()
    try:
        before_reviews = db.scalar(
            select(func.count()).select_from(ReviewDecision)
        )
        before_audits = db.scalar(select(func.count()).select_from(AuditLog))
        incident_before = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        status_before = incident_before.status.value
    finally:
        db.close()

    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={"decision": "not_a_real_decision", "reviewer_id": 1},
    )
    assert response.status_code == 422

    db = SessionLocal()
    try:
        after_reviews = db.scalar(select(func.count()).select_from(ReviewDecision))
        after_audits = db.scalar(select(func.count()).select_from(AuditLog))
        incident_after = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        assert after_reviews == before_reviews
        assert after_audits == before_audits
        assert incident_after.status.value == status_before
    finally:
        db.close()


@pytest.mark.integration
def test_latest_review_decision_updates_status(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "rejected",
            "reviewer_id": 1,
            "reason": "Masked evidence was reviewed as a false-positive disposition.",
        },
    )
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Additional masked evidence supports remediation review.",
        },
    )

    db = SessionLocal()
    try:
        incident = db.scalar(
            select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID)
        )
        latest = db.scalar(
            select(ReviewDecision)
            .where(ReviewDecision.incident_id == SEED_INCIDENT_ID)
            .order_by(ReviewDecision.timestamp.desc(), ReviewDecision.id.desc())
        )
        assert latest is not None
        assert latest.decision == "approved"
        assert incident.status == IncidentStatus.CONFIRMED_INCIDENT
    finally:
        db.close()


# --- Risk 2: audit safety ---


def test_audit_masks_phone_in_comment():
    masked = audit_safety_service.prepare_review_comment(
        "Reviewer note with phone 9841234567 in logs."
    )
    assert "9841234567" not in masked
    assert "[MASKED]" in masked


def test_audit_rejects_developer_fault_in_comment():
    with pytest.raises(audit_safety_service.AuditSafetyError):
        audit_safety_service.prepare_review_comment(
            "This is developer fault for sure."
        )


def test_audit_rejects_proven_cause_in_comment():
    with pytest.raises(audit_safety_service.AuditSafetyError):
        audit_safety_service.prepare_review_comment("We found the proven cause.")


def test_audit_details_sanitize_wallet_and_jwt():
    details = audit_safety_service.validate_and_sanitize_audit_details(
        {
            "incident_id": SEED_INCIDENT_ID,
            "note": "wallet WALLET-NP-88291 and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.x",
        }
    )
    blob = json.dumps(details)
    assert "WALLET-NP-88291" not in blob
    assert "eyJhbGciOiJIUzI1NiJ9" not in blob


@pytest.mark.integration
def test_review_comment_with_phone_masked_in_db_and_audit(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "comment": "Masked review references phone 9841234567.",
        },
    )
    assert response.status_code == 200

    audit_resp = client.get("/audit-logs", params={"incident_id": SEED_INCIDENT_ID})
    blob = json.dumps(audit_resp.json())
    assert "9841234567" not in blob

    db = SessionLocal()
    try:
        review = db.scalars(
            select(ReviewDecision)
            .where(ReviewDecision.incident_id == SEED_INCIDENT_ID)
            .order_by(ReviewDecision.timestamp.desc())
        ).first()
        assert review is not None
        assert review.comment is not None
        assert "9841234567" not in review.comment
    finally:
        db.close()


@pytest.mark.integration
def test_review_comment_overclaim_rejected(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "comment": "confirmed blame on the developer fault.",
        },
    )
    assert response.status_code == 422
    assert "overclaim" in response.json()["detail"].lower() or "blame" in response.json()["detail"].lower()


@pytest.mark.integration
def test_get_audit_logs_no_raw_leaks_or_overclaim(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "inconclusive",
            "reviewer_id": 1,
            "comment": "Likely cause needs more supporting evidence; human review required.",
        },
    )
    audit_resp = client.get("/audit-logs", params={"incident_id": SEED_INCIDENT_ID})
    blob = json.dumps(audit_resp.json()).lower()
    for substring in RAW_LEAK_SUBSTRINGS:
        assert substring.lower() not in blob
    for phrase in ("proven cause", "developer fault", "confirmed blame", "guaranteed cause"):
        assert phrase not in blob


# --- Risk 3: fix verification gate (Phase 9 precondition only) ---


@pytest.mark.integration
def test_gate_no_review_not_allowed(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    db = SessionLocal()
    try:
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
        with pytest.raises(fix_verification_gate_service.FixVerificationNotAllowedError):
            fix_verification_gate_service.assert_fix_verification_allowed(
                db, SEED_INCIDENT_ID
            )
    finally:
        db.close()


@pytest.mark.integration
def test_gate_approved_confirmed_allowed(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    review = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Masked evidence supports a human-owned remediation action.",
        },
    )
    assert review.status_code == 200, review.text
    remediation = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/remediation-actions",
        json={
            "action_type": "redaction_rule_update",
            "action_description": "Update the reviewed logging redaction rule.",
            "affected_component": "wallet logging middleware",
            "assigned_owner": "wallet platform team",
            "status": "awaiting_retest",
            "priority": "high",
            "retest_required": True,
        },
    )
    assert remediation.status_code == 200, remediation.text
    retest = client.post(
        f"/live-monitor/incidents/{SEED_INCIDENT_ID}/retest-event",
        json={},
    )
    assert retest.status_code == 200, retest.text
    db = SessionLocal()
    try:
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()


@pytest.mark.integration
@pytest.mark.parametrize("decision", ["rejected", "inconclusive", "request_more_evidence"])
def test_gate_non_approved_not_allowed(client: TestClient, seeded_db, decision: str):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": decision,
            "reviewer_id": 1,
            "reason": f"Masked evidence supports the {decision} review decision.",
        },
    )
    db = SessionLocal()
    try:
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()


@pytest.mark.integration
def test_gate_llm_without_review_not_allowed(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    explain = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    )
    assert explain.status_code == 200

    db = SessionLocal()
    try:
        llm_count = db.scalar(
            select(func.count())
            .select_from(LlmReport)
            .where(LlmReport.incident_id == SEED_INCIDENT_ID)
        )
        assert llm_count >= 1
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()


@pytest.mark.integration
def test_gate_root_cause_without_review_not_allowed(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    db = SessionLocal()
    try:
        assert not fix_verification_gate_service.can_start_fix_verification(
            db, SEED_INCIDENT_ID
        )
    finally:
        db.close()


# --- Regression ---


@pytest.mark.integration
def test_review_endpoint_regression(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Masked evidence supports remediation review.",
        },
    )
    assert response.status_code == 200
    assert response.json()["incident_status"] == IncidentStatus.CONFIRMED_INCIDENT.value


@pytest.mark.integration
def test_audit_logs_endpoint_regression(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/review",
        json={
            "decision": "approved",
            "reviewer_id": 1,
            "reason": "Masked evidence supports remediation review.",
        },
    )
    response = client.get("/audit-logs", params={"incident_id": SEED_INCIDENT_ID})
    assert response.status_code == 200
    assert response.json()["total"] >= 1


@pytest.mark.integration
def test_phase9_verify_fix_endpoint_present():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    assert any("/verify-fix" in p for p in paths)
