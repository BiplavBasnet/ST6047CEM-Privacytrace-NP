"""Phase 6 tests: Privacy Causality Engine and incident analyse API."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models.enums import EvidenceType, ParsingStatus
from app.services import causality_engine, confidence_service
from app.services.causality_engine import EvidenceContext, score_candidate_cause

RAW_LEAK_SUBSTRINGS = (
    "9841234567",
    "WALLET-NP-88291",
    "SYNTHETIC_FAKE_PAYLOAD.NOT_A_REAL_TOKEN",
    "pk_test_np_fake_12345",
)

SEED_INCIDENT_ID = "INC-SEED-001"


def test_score_to_band_boundaries():
    rules = confidence_service.load_confidence_rules()
    assert confidence_service.score_to_band(0.74, rules) == "medium"
    assert confidence_service.score_to_band(0.75, rules) == "high"
    assert confidence_service.score_to_band(0.44, rules) == "low"
    assert confidence_service.score_to_band(0.45, rules) == "medium"


def test_apply_penalties_reduces_score():
    rules = confidence_service.load_confidence_rules()
    final, labels = confidence_service.apply_penalties(
        0.90, ["missing_code_scan"], rules
    )
    assert final < 0.90
    assert labels


def test_dependency_cause_capped():
    rules = causality_engine.load_root_cause_rules()
    dep_rule = next(
        c for c in rules["causes"] if c["likely_root_cause"] == "suspicious_dependency_introduced"
    )
    ctx = EvidenceContext(
        incident_id="INC-TEST",
        incident=type("I", (), {"affected_endpoint": "/x", "affected_service": "s"})(),
        evidence_types_present={"trivy_report"},
        evidence_ids_by_type={"trivy_report": ["EVD-S1-TRIVY-001"]},
        supporting_evidence_ids={"EVD-S1-TRIVY-001"},
        masked_messages=["np-wallet-helper"],
    )
    scored = score_candidate_cause(ctx, dep_rule)
    assert scored.final_score <= 0.44
    assert scored.supporting_only is True


def test_missing_semgrep_lowers_confidence():
    rules = causality_engine.load_root_cause_rules()
    unsafe_rule = next(
        c for c in rules["causes"] if c["likely_root_cause"] == "unsafe_request_body_logging"
    )
    base_kwargs = dict(
        incident_id=SEED_INCIDENT_ID,
        incident=type(
            "I",
            (),
            {
                "affected_endpoint": "/api/v1/wallet/transfer",
                "affected_service": "wallet-service",
            },
        )(),
        sensitive_types={"nepal_phone", "wallet_id", "transaction_ref"},
        event_types={"request_body_logged"},
        raw_references=["rule:privacytrace.unsafe-request-body-logging"],
    )
    full_ctx = EvidenceContext(
        **base_kwargs,
        evidence_types_present={"api_log", "semgrep_report"},
        evidence_ids_by_type={
            "api_log": ["EVD-S1-API-001"],
            "semgrep_report": ["EVD-S1-SAST-001"],
        },
        supporting_evidence_ids={"EVD-S1-API-001", "EVD-S1-SAST-001"},
    )
    partial_ctx = EvidenceContext(
        **base_kwargs,
        evidence_types_present={"api_log"},
        evidence_ids_by_type={"api_log": ["EVD-S1-API-001"]},
        supporting_evidence_ids={"EVD-S1-API-001"},
    )
    full_score = score_candidate_cause(full_ctx, unsafe_rule)
    partial_score = score_candidate_cause(partial_ctx, unsafe_rule)
    assert partial_score.final_score < full_score.final_score
    assert any("code scan" in m.lower() for m in partial_score.missing_evidence)


def test_unsafe_logging_scores_highest_for_scenario_signals():
    rules = causality_engine.load_root_cause_rules()
    unsafe_rule = next(
        c for c in rules["causes"] if c["likely_root_cause"] == "unsafe_request_body_logging"
    )
    dep_rule = next(
        c for c in rules["causes"] if c["likely_root_cause"] == "suspicious_dependency_introduced"
    )
    ctx = EvidenceContext(
        incident_id=SEED_INCIDENT_ID,
        incident=type(
            "I",
            (),
            {
                "affected_endpoint": "/api/v1/wallet/transfer",
                "affected_service": "wallet-service",
            },
        )(),
        sensitive_types={"nepal_phone", "wallet_id", "transaction_ref"},
        evidence_types_present={"api_log", "semgrep_report", "trivy_report"},
        evidence_ids_by_type={
            "api_log": ["EVD-S1-API-001"],
            "semgrep_report": ["EVD-S1-SAST-001"],
            "trivy_report": ["EVD-S1-TRIVY-001"],
        },
        supporting_evidence_ids={"EVD-S1-API-001", "EVD-S1-SAST-001", "EVD-S1-TRIVY-001"},
        event_types={"request_body_logged"},
        raw_references=["rule:privacytrace.unsafe-request-body-logging"],
        events=[],
    )
    unsafe = score_candidate_cause(ctx, unsafe_rule)
    dep = score_candidate_cause(ctx, dep_rule)
    assert unsafe.final_score > dep.final_score


def test_app_has_incident_analyse_route():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    assert "/incidents/analyse" in paths


@pytest.mark.integration
def test_full_pipeline_analyse_scenario1(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    response = client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})
    assert response.status_code == 200
    data = response.json()
    assert data["total_scored"] > 0
    assert data["results"][0]["status"] == "analysed"


@pytest.mark.integration
def test_incident_detail_top_cause(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})

    detail = client.get(f"/incidents/{SEED_INCIDENT_ID}").json()
    assert detail["status"] == "under_review"
    scores = detail["root_cause_scores"]
    assert len(scores) >= 1
    top = scores[0]
    assert top["likely_root_cause"] == "unsafe_request_body_logging"
    assert top["confidence_band"] == "high"
    assert top["human_review_required"] is True
    assert "confirmed" not in (top.get("recommended_fix") or "").lower()


@pytest.mark.integration
def test_trace_no_raw_leak(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})

    trace = client.get(f"/incidents/{SEED_INCIDENT_ID}/trace").json()
    payload = json.dumps(trace)
    for raw in RAW_LEAK_SUBSTRINGS:
        assert raw not in payload
    assert trace["detection_count"] > 0
    assert len(trace["likely_root_causes"]) >= 1
    assert trace["disclaimer"]
    assert trace["likely_root_causes"][0]["wording"] == "likely cause"


@pytest.mark.integration
def test_suspicious_dependency_not_rank_one(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})

    trace = client.get(f"/incidents/{SEED_INCIDENT_ID}/trace").json()
    ranked = trace["likely_root_causes"]
    assert ranked[0]["likely_root_cause"] != "suspicious_dependency_introduced"


@pytest.mark.integration
def test_analyse_idempotent_then_force(client: TestClient, seeded_db):
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})

    first = client.post(
        "/incidents/analyse",
        json={"incident_id": SEED_INCIDENT_ID},
    )
    assert first.status_code == 200
    assert first.json()["results"][0]["skipped"] is True

    second = client.post(
        "/incidents/analyse",
        json={"incident_id": SEED_INCIDENT_ID, "force": True},
    )
    assert second.status_code == 200
    assert second.json()["results"][0]["skipped"] is False


@pytest.mark.integration
def test_analyse_without_detections_returns_422(client: TestClient, seeded_db):
    from sqlalchemy import select

    from app.database import SessionLocal
    from app.models import Incident
    from app.models.enums import IncidentStatus, Severity

    incident_id = "INC-NO-DET-001"
    db = SessionLocal()
    try:
        if not db.scalar(select(Incident).where(Incident.incident_id == incident_id)):
            db.add(
                Incident(
                    incident_id=incident_id,
                    title="No detections incident",
                    affected_endpoint="/api/v1/wallet/transfer",
                    affected_service="wallet-service",
                    status=IncidentStatus.NEW,
                    severity=Severity.HIGH,
                )
            )
            db.commit()
    finally:
        db.close()

    response = client.post("/incidents/analyse", json={"incident_id": incident_id})
    assert response.status_code == 422


@pytest.mark.integration
def test_health_still_works_phase6(client: TestClient, seeded_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"
