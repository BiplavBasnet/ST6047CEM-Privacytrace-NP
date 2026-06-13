"""Phase 7 tests: Guarded LLM Investigation Assistant."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.tests.route_test_utils import registered_routes
from app.models import LlmReport
from app.services import (
    llm_context_service,
    llm_safety_service,
    template_explanation_service,
)
from app.tests.test_phase6 import RAW_LEAK_SUBSTRINGS, SEED_INCIDENT_ID


def _run_pipeline_to_analyse(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


@pytest.mark.integration
def test_context_builder_has_ranking_and_masked_fields(client: TestClient, seeded_db):
    from app.database import SessionLocal

    _run_pipeline_to_analyse(client)
    db = SessionLocal()
    try:
        context = llm_context_service.build_llm_context(db, SEED_INCIDENT_ID)
    finally:
        db.close()

    assert context["incident_id"] == SEED_INCIDENT_ID
    assert len(context["root_cause_ranking"]) >= 1
    assert context["rules"]["raw_sensitive_values_forbidden"] is True
    assert "masked_evidence" in context
    assert "masked_detection_summary" in context
    h = llm_context_service.hash_context(context)
    assert h.startswith("sha256:")


def test_hash_context_is_deterministic():
    ctx = {"incident_id": "INC-1", "root_cause_ranking": []}
    assert llm_context_service.hash_context(ctx) == llm_context_service.hash_context(ctx)


def test_input_guard_blocks_nepal_phone():
    unsafe = {"incident_id": "X", "note": "9841234567"}
    result = llm_safety_service.validate_input_context(unsafe)
    assert not result.safe
    assert result.violation_codes


def test_input_guard_blocks_jwt():
    unsafe = {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}
    result = llm_safety_service.validate_input_context(unsafe)
    assert not result.safe


def test_input_guard_blocks_api_key():
    unsafe = {"key": "pk_test_np_fake_12345"}
    result = llm_safety_service.validate_input_context(unsafe)
    assert not result.safe


def test_input_guard_allows_masked_context():
    safe = {
        "incident_id": SEED_INCIDENT_ID,
        "root_cause_ranking": [
            {
                "rank": 1,
                "likely_root_cause": "unsafe_request_body_logging",
                "supporting_evidence_ids": ["EVD-S1-API-001"],
            }
        ],
        "masked_evidence": [{"evidence_id": "EVD-S1-API-001", "masked_message": "[REDACTED]"}],
    }
    result = llm_safety_service.validate_input_context(safe)
    assert result.safe


def test_evidence_grounding_requires_ids_or_missing_language():
    known = {"EVD-S1-API-001"}
    bad = {
        "likely_cause_explanation": "Something happened without references.",
        "alternative_hypotheses": [],
    }
    errors = llm_safety_service.check_evidence_grounding(bad, known)
    assert "likely_cause_missing_evidence_ids" in errors

    good = {
        "likely_cause_explanation": "Supporting evidence suggests EVD-S1-API-001 is relevant.",
        "alternative_hypotheses": [],
    }
    assert not llm_safety_service.check_evidence_grounding(good, known)


def test_overclaim_detection():
    output = {
        "incident_summary": "This is the proven cause of the leak.",
        "likely_cause_explanation": "x",
        "supporting_evidence_summary": "x",
        "alternative_hypotheses": [],
        "missing_evidence_questions": [],
        "recommended_fix_draft": "x",
        "fix_verification_checklist": [],
        "human_review_note": "x",
        "safety_notes": {},
    }
    found = llm_safety_service.check_overclaim_phrases(output)
    assert any("overclaim" in e for e in found)


def test_template_output_has_all_required_keys():
    context = {
        "incident_id": SEED_INCIDENT_ID,
        "affected_endpoint": "/api/v1/wallet/transfer",
        "affected_service": "wallet-service",
        "masked_detection_summary": [{"detection_id": "DET-1"}],
        "masked_evidence": [],
        "root_cause_ranking": [
            {
                "rank": 1,
                "likely_root_cause": "unsafe_request_body_logging",
                "confidence": 0.8,
                "confidence_band": "high",
                "supporting_evidence_ids": ["EVD-S1-API-001"],
                "missing_evidence": ["deployment log"],
                "recommended_fix": "Disable request-body logging in production.",
            },
            {
                "rank": 2,
                "likely_root_cause": "jwt_or_token_leakage",
                "confidence": 0.5,
                "confidence_band": "medium",
                "supporting_evidence_ids": ["EVD-S1-SAST-001"],
                "missing_evidence": [],
                "recommended_fix": "Redact tokens in logs.",
            },
        ],
    }
    output = template_explanation_service.generate_investigation_output(context)
    rules = llm_safety_service.load_llm_safety_rules()
    for key in rules["required_output_keys"]:
        assert key in output
    assert "likely" in output["likely_cause_explanation"].lower()
    assert output["safety_notes"]["human_review_required"] is True


def test_fix_draft_from_top_ranked_cause():
    fix_text = "Disable request-body logging in production."
    context = {
        "incident_id": SEED_INCIDENT_ID,
        "affected_endpoint": "/x",
        "affected_service": "svc",
        "masked_detection_summary": [],
        "masked_evidence": [],
        "root_cause_ranking": [
            {
                "rank": 1,
                "likely_root_cause": "unsafe_request_body_logging",
                "confidence_band": "high",
                "supporting_evidence_ids": ["EVD-S1-API-001"],
                "missing_evidence": [],
                "recommended_fix": fix_text,
            }
        ],
    }
    output = template_explanation_service.generate_investigation_output(context)
    assert fix_text in output["recommended_fix_draft"]


def test_app_has_explain_and_llm_reports_routes():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    assert "/incidents/{incident_id}/explain" in paths
    assert "/incidents/{incident_id}/llm-reports" in paths


@pytest.mark.integration
def test_full_pipeline_explain_template(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["provider_used"] == "template"
    assert data["safety_status"] in ("passed", "flagged")
    assert data["output"]["incident_summary"]
    assert "likely" in data["output"]["likely_cause_explanation"].lower()


@pytest.mark.integration
def test_explain_response_no_raw_leaks(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template", "force_template": True},
    )
    payload = json.dumps(response.json())
    for raw in RAW_LEAK_SUBSTRINGS:
        assert raw not in payload


@pytest.mark.integration
def test_explain_mentions_evidence_ids(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    data = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    ).json()
    blob = json.dumps(data["output"])
    assert "EVD-" in blob


@pytest.mark.integration
def test_explain_persists_llm_report_row(client: TestClient, seeded_db):
    from app.database import SessionLocal

    _run_pipeline_to_analyse(client)
    report_id = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    ).json()["report_id"]

    db = SessionLocal()
    try:
        row = db.scalar(select(LlmReport).where(LlmReport.report_id == report_id))
        assert row is not None
        assert row.incident_id == SEED_INCIDENT_ID
        assert row.input_context_hash.startswith("sha256:")
        from app.services import llm_investigation_service

        assert llm_investigation_service.get_report_output_json(row).get("incident_summary")
    finally:
        db.close()


@pytest.mark.integration
def test_list_llm_reports(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    )
    listing = client.get(f"/incidents/{SEED_INCIDENT_ID}/llm-reports")
    assert listing.status_code == 200
    body = listing.json()
    assert body["incident_id"] == SEED_INCIDENT_ID
    assert body["total"] >= 1
    assert body["reports"][0]["report_id"].startswith("LLM-")


@pytest.mark.integration
def test_explain_unknown_incident_404(client: TestClient, seeded_db):
    response = client.post(
        "/incidents/INC-NONEXISTENT/explain",
        json={"provider": "template"},
    )
    assert response.status_code == 404


@pytest.mark.integration
def test_explain_without_analyse_422(client: TestClient, seeded_db):
    from app.database import SessionLocal
    from app.models import Incident
    from app.models.enums import IncidentStatus, Severity

    incident_id = "INC-NO-RCS-001"
    db = SessionLocal()
    try:
        if not db.scalar(select(Incident).where(Incident.incident_id == incident_id)):
            db.add(
                Incident(
                    incident_id=incident_id,
                    title="No root cause scores",
                    affected_endpoint="/api/v1/wallet/transfer",
                    affected_service="wallet-service",
                    status=IncidentStatus.NEW,
                    severity=Severity.HIGH,
                )
            )
            db.commit()
    finally:
        db.close()

    response = client.post(
        f"/incidents/{incident_id}/explain",
        json={"provider": "template"},
    )
    assert response.status_code == 422


@pytest.mark.integration
def test_ollama_unavailable_falls_back_to_template(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    with patch(
        "app.services.llm_investigation_service.llm_provider_service.is_ollama_available",
        return_value=False,
    ):
        data = client.post(
            f"/incidents/{SEED_INCIDENT_ID}/explain",
            json={"provider": "ollama"},
        ).json()
    assert data["provider_used"] == "template"


@pytest.mark.integration
def test_blocked_input_returns_422(client: TestClient, seeded_db):
    _run_pipeline_to_analyse(client)
    unsafe_context = {
        "incident_id": SEED_INCIDENT_ID,
        "root_cause_ranking": [],
        "leak": "9841234567",
    }
    with patch(
        "app.services.llm_investigation_service.llm_context_service.build_llm_context",
        return_value=unsafe_context,
    ):
        response = client.post(
            f"/incidents/{SEED_INCIDENT_ID}/explain",
            json={"provider": "template"},
        )
    assert response.status_code == 422
    assert response.json()["detail"]["safety_status"] == "blocked_input"


@pytest.mark.integration
def test_health_still_works_phase7(client: TestClient, seeded_db):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"


@pytest.mark.integration
def test_no_dashboard_or_phase11_routes():
    paths = [getattr(r, "path", "") for r in registered_routes(app)]
    for forbidden in ("/dashboard", "/phase11", "/frontend"):
        assert not any(forbidden in p for p in paths)


@pytest.mark.ollama
@pytest.mark.integration
def test_ollama_explain_when_available(client: TestClient, seeded_db):
    from app.services import llm_provider_service

    if not llm_provider_service.is_ollama_available():
        pytest.skip("Ollama is not running locally")

    _run_pipeline_to_analyse(client)
    response = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "ollama"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["provider_used"] in ("ollama", "template")
    assert data["output"]["human_review_note"]
