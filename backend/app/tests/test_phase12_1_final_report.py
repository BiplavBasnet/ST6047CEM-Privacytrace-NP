"""Phase 12.1 — final investigation report export endpoints."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from app.db.seed_phase2 import SEED_INCIDENT_ID
from app.tests.test_phase10_reports_metrics import _full_workflow, _record_safe_retest

pytestmark = pytest.mark.usefixtures("seeded_db")


def _prepare(client: TestClient) -> None:
    _full_workflow(client)


def test_final_report_json_endpoint(client: TestClient):
    _prepare(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["metadata"]["incident_id"] == SEED_INCIDENT_ID
    assert body["incident"]["incident_id"] == SEED_INCIDENT_ID


def test_final_report_html_endpoint(client: TestClient):
    _prepare(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.html")
    assert response.status_code == 200, response.text
    assert "text/html" in response.headers.get("content-type", "")
    assert "Final Investigation Report" in response.text


def test_final_report_pdf_endpoint(client: TestClient):
    _prepare(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.pdf")
    assert response.status_code == 200, response.text
    assert response.headers.get("content-type", "").startswith("application/pdf")
    assert response.content[:4] == b"%PDF"


def test_evidence_summary_csv_endpoint(client: TestClient):
    _prepare(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/evidence-summary.csv")
    assert response.status_code == 200, response.text
    assert "evidence_id" in response.text
    assert "role_in_investigation" in response.text


def test_final_report_bundle_zip_endpoint(client: TestClient):
    _prepare(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report-bundle.zip")
    assert response.status_code == 200, response.text
    assert "zip" in response.headers.get("content-type", "")


def test_final_report_includes_incident_details(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert body["incident"]["title"]
    assert body["incident"]["status"]


def test_final_report_includes_masked_detections(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert len(body["detections"]) > 0
    for det in body["detections"]:
        assert det.get("masked_value")
        assert "raw_value" not in det


def test_final_report_includes_evidence_chain(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert len(body["evidence_chain"]) > 0


def test_final_report_includes_root_cause_ranking(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert len(body["root_cause_ranking"]) > 0


def test_final_report_includes_human_review_when_available(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert body["human_review"]["decision"] == "approved"


def test_final_report_includes_fix_verification_section(client: TestClient):
    _prepare(client)
    evidence_id = _record_safe_retest(client)
    verification = client.post(
        f"/incidents/{SEED_INCIDENT_ID}/verify-fix",
        json={"retest_evidence_ids": [evidence_id], "requested_by": 1},
    )
    assert verification.status_code == 422, verification.text
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert body.get("fix_verification") is None or body["fix_verification"].get("verification_status") in {None, "not_run", "inconclusive"}


def test_final_report_includes_recommendations_and_limitations(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    assert len(body["recommendations"]) > 0
    assert len(body["limitations"]) > 0
    assert len(body["privacy_safety_controls"]) > 0


def test_final_report_guarded_explanation_section(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    ge = body["guarded_explanation"]
    assert ge.get("explanation_text") or ge.get("not_generated_message")


def test_final_report_missing_incident_404(client: TestClient):
    response = client.get("/reports/incidents/INC-NOT-REAL/final-report.json")
    assert response.status_code == 404


def test_final_report_json_has_required_sections(client: TestClient):
    _prepare(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()
    for key in (
        "metadata",
        "executive_summary",
        "incident",
        "detections",
        "evidence_chain",
        "root_cause_ranking",
        "guarded_explanation",
        "human_review",
        "fix_verification",
        "audit_summary",
        "recommendations",
        "privacy_safety_controls",
        "limitations",
        "appendix",
    ):
        assert key in body
