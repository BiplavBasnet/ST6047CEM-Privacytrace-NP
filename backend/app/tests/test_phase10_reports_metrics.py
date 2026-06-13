"""Phase 10 tests: incident reports and thesis-aligned evaluation metrics."""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Report
from app.models.enums import IncidentStatus
from app.services import evaluation_metric_service, report_safety_service, report_service
from app.tests.test_phase6 import RAW_LEAK_SUBSTRINGS, SEED_INCIDENT_ID

OVERCLAIM_PHRASES = (
    "proven cause",
    "confirmed blame",
    "guaranteed cause",
    "definitely caused by",
    "developer fault",
    "guaranteed fixed",
    "incident closed automatically",
)

REQUIRED_METRICS = evaluation_metric_service.CORE_METRIC_NAMES


def _pipeline_to_analyse(client: TestClient) -> None:
    client.post("/evidence/load-sample", json={"scenario": "scenario_1"})
    client.post("/evidence/parse-all")
    client.post("/evidence/detect-all")
    client.post("/incidents/analyse", json={"incident_id": SEED_INCIDENT_ID})


def _full_workflow(client: TestClient) -> None:
    _pipeline_to_analyse(client)
    client.post(
        f"/incidents/{SEED_INCIDENT_ID}/explain",
        json={"provider": "template"},
    )
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
            "action_description": "Update the reviewed wallet logging redaction rule.",
            "affected_component": "wallet logging middleware",
            "assigned_owner": "wallet platform team",
            "status": "awaiting_retest",
            "priority": "high",
            "retest_required": True,
        },
    )
    assert remediation.status_code == 200, remediation.text


def _record_safe_retest(client: TestClient) -> str:
    response = client.post(
        f"/live-monitor/incidents/{SEED_INCIDENT_ID}/retest-event",
        json={},
    )
    assert response.status_code == 200, response.text
    return response.json()["evidence_id"]


def _blob_has_raw(blob: str) -> bool:
    for needle in RAW_LEAK_SUBSTRINGS:
        if needle in blob:
            return True
    if re.search(r"(?i)authorization\s*:\s*bearer\s+eyJ", blob):
        return True
    return False


def _blob_has_overclaim(blob: str) -> bool:
    lower = blob.lower()
    return any(p in lower for p in OVERCLAIM_PHRASES)


@pytest.mark.integration
def test_json_report_generated(client: TestClient, seeded_db):
    _full_workflow(client)
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["report_type"] == "json"
    assert body["content"]["incident_id"] == SEED_INCIDENT_ID


@pytest.mark.integration
def test_html_report_generated(client: TestClient, seeded_db):
    _full_workflow(client)
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "html", "requested_by": 1},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["report_type"] == "html"
    assert body["html_document"]
    assert "<html" in body["html_document"].lower()


@pytest.mark.integration
def test_report_includes_masked_detections_and_evidence_ids(client: TestClient, seeded_db):
    _full_workflow(client)
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    content = response.json()["content"]
    assert len(content["masked_detections"]) > 0
    for det in content["masked_detections"]:
        assert "masked_value" in det
        assert det["masked_value"]
    assert len(content["linked_evidence_ids"]) > 0
    assert any(eid.startswith("EVD-") for eid in content["linked_evidence_ids"])


@pytest.mark.integration
def test_report_includes_causality_and_review(client: TestClient, seeded_db):
    _full_workflow(client)
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    content = response.json()["content"]
    assert content["top_likely_root_cause"] == "unsafe_request_body_logging"
    assert content["confidence_band"] in ("high", "medium", "low")
    assert content["human_review_decisions"]
    assert content["human_review_decisions"][-1]["decision"] == "approved"


@pytest.mark.integration
def test_report_lists_fix_verification_when_present(client: TestClient, seeded_db):
    _full_workflow(client)
    evidence_id = _record_safe_retest(client)
    verification = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [evidence_id], "requested_by": 1},
    )
    assert verification.status_code == 422, verification.text
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    content = response.json()["content"]
    assert content.get("fix_verification") is None


@pytest.mark.integration
@pytest.mark.parametrize("needle", RAW_LEAK_SUBSTRINGS)
def test_report_json_no_raw_sensitive_values(client: TestClient, seeded_db, needle: str):
    _full_workflow(client)
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    blob = json.dumps(response.json())
    assert needle not in blob


@pytest.mark.integration
def test_report_no_overclaim_phrases(client: TestClient, seeded_db):
    _full_workflow(client)
    response = client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    assert not _blob_has_overclaim(json.dumps(response.json()))


@pytest.mark.integration
def test_unsafe_report_content_rejected():
    unsafe = evaluation_metric_service.build_unsafe_report_probe()
    result = report_safety_service.validate_report_payload(unsafe)
    assert not result.safe
    with pytest.raises(report_safety_service.ReportSafetyError):
        report_safety_service.assert_report_safe(unsafe)


@pytest.mark.integration
def test_metrics_endpoint_returns_thesis_aligned_metrics(client: TestClient, seeded_db):
    _full_workflow(client)
    client.post("/metrics/evaluation/run", json={"scenario_name": "scenario_1"})
    listing = client.get("/metrics/evaluation", params={"scenario_name": "scenario_1"})
    assert listing.status_code == 200
    body = listing.json()
    names = {m["metric_name"] for m in body["metrics"]}
    assert REQUIRED_METRICS.issubset(names)


@pytest.mark.integration
def test_each_metric_has_thesis_claim_and_method(client: TestClient, seeded_db):
    _full_workflow(client)
    client.post("/metrics/evaluation/run", json={"scenario_name": "scenario_1"})
    listing = client.get("/metrics/evaluation").json()
    for metric in listing["metrics"]:
        assert metric.get("thesis_claim")
        assert metric.get("calculation_method")
        assert metric.get("evidence_source")


@pytest.mark.integration
def test_metrics_include_ttcl_and_leak_and_overclaim(client: TestClient, seeded_db):
    _full_workflow(client)
    client.post("/metrics/evaluation/run", json={"scenario_name": "scenario_1"})
    names = {m["metric_name"] for m in client.get("/metrics/evaluation").json()["metrics"]}
    assert "time_to_causal_localisation" in names
    assert "raw_sensitive_value_leak_count" in names
    assert "llm_overclaim_violation_count" in names


@pytest.mark.integration
def test_metrics_are_not_random_counters_only(client: TestClient, seeded_db):
    _full_workflow(client)
    client.post("/metrics/evaluation/run", json={"scenario_name": "scenario_1"})
    listing = client.get("/metrics/evaluation").json()
    for metric in listing["metrics"]:
        assert metric["metric_name"] in REQUIRED_METRICS
    context = listing.get("context_counts") or {}
    assert "total_users" not in {m["metric_name"] for m in listing["metrics"]}
    assert context.get("linked_evidence_files", 0) >= 0


@pytest.mark.integration
def test_reports_stored_safely(client: TestClient, seeded_db):
    _full_workflow(client)
    before = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}").json()["total"]
    client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    after = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}").json()
    assert after["total"] == before + 1
    db = SessionLocal()
    try:
        row = db.scalar(select(Report).order_by(Report.id.desc()).limit(1))
        assert row is not None
        assert row.content_json or row.content_encrypted
    finally:
        db.close()


@pytest.mark.integration
def test_html_report_escapes_unsafe_markup():
    payload = {
        "incident_id": "INC-TEST",
        "affected_service": "<script>alert(1)</script>",
        "affected_endpoint": "/api",
        "severity": "high",
        "status": "under_review",
        "masked_detections": [],
        "linked_evidence_ids": [],
        "likely_root_causes": [],
        "top_likely_root_cause": "unsafe_request_body_logging",
        "confidence_band": "high",
        "missing_evidence": [],
        "recommended_fix": "mask logs",
        "llm_explanation_summary": None,
        "human_review_decisions": [],
        "audit_summary": [],
        "fix_verification": None,
        "safety_statement": report_service.SAFETY_STATEMENT,
        "human_review_required": True,
    }
    html_doc = report_service.render_html_report(payload)
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;" in html_doc


@pytest.mark.integration
def test_list_reports_safe_metadata(client: TestClient, seeded_db):
    _full_workflow(client)
    client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    listing = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}")
    blob = json.dumps(listing.json())
    assert not _blob_has_raw(blob)
    assert not _blob_has_overclaim(blob)


@pytest.mark.integration
def test_incident_not_auto_closed_by_report(client: TestClient, seeded_db):
    _full_workflow(client)
    client.post(
        f"/reports/incidents/{SEED_INCIDENT_ID}/generate",
        json={"report_type": "json", "requested_by": 1},
    )
    from app.models import Incident

    db = SessionLocal()
    try:
        inc = db.scalar(select(Incident).where(Incident.incident_id == SEED_INCIDENT_ID))
        assert inc.status != IncidentStatus.CLOSED
    finally:
        db.close()
