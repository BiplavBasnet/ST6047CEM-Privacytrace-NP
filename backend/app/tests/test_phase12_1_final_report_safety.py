"""Phase 12.1 — final report safety sanitization."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.db.seed_phase2 import SEED_INCIDENT_ID
from app.schemas.final_report_schema import (
    FinalInvestigationReport,
    FinalReportExecutiveSummary,
    FinalReportFixVerification,
    FinalReportGuardedExplanation,
    FinalReportHumanReview,
    FinalReportIncidentSection,
    FinalReportMetadata,
)
from app.services import final_report_pdf_service, final_report_service, report_safety_service
from app.tests.test_phase10_reports_metrics import OVERCLAIM_PHRASES, _full_workflow

UNSAFE_FRAGMENTS = [
    ("9841234567", "9841234567"),
    ("WALLET-NP-88291", "WALLET-NP-88291"),
    ("pk_test_np_fake_12345", "pk_test_np"),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.sig", "eyJhbGci"),
    ("Bearer abcdef.ghijklm.opqrstuvwx", "Bearer abcdef"),
    ("Authorization: Bearer secret-token-value", "secret-token-value"),
    ("-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY"),
    ("password=hunter2", "hunter2"),
]


@pytest.mark.parametrize("unsafe,fragment", UNSAFE_FRAGMENTS)
def test_sanitize_export_text_masks_or_omits(unsafe: str, fragment: str):
    result = report_safety_service.sanitize_export_text(unsafe)
    if result.value:
        assert fragment not in result.value
    assert unsafe not in (result.value or "")


def test_sanitize_export_text_replaces_overclaim():
    result = report_safety_service.sanitize_export_text("This was the proven cause of the breach")
    assert result.value
    assert "proven cause" not in result.value.lower()


def test_warnings_never_echo_unsafe_value():
    result = report_safety_service.sanitize_export_text("phone 9841234567")
    blob = json.dumps({"warnings": result.warnings})
    assert "9841234567" not in blob


def test_sanitize_final_report_dict_unit():
    payload = {
        "executive_summary": {"incident_summary": "likely cause with supporting evidence"},
        "detections": [{"masked_value": "pk_****demo"}],
    }
    cleaned, _warnings = report_safety_service.sanitize_final_report_dict(payload)
    assert cleaned["detections"][0]["masked_value"]


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_json_export_no_raw_leaks(client: TestClient):
    _full_workflow(client)
    blob = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").text
    for _unsafe, fragment in UNSAFE_FRAGMENTS:
        if len(fragment) > 6:
            assert fragment not in blob


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_html_export_no_raw_leaks(client: TestClient):
    _full_workflow(client)
    blob = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.html").text
    for _unsafe, fragment in UNSAFE_FRAGMENTS:
        if len(fragment) > 6:
            assert fragment not in blob


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_pdf_export_no_raw_leaks(client: TestClient):
    _full_workflow(client)
    blob = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.pdf").content.decode(
        "latin-1", errors="ignore"
    )
    assert "9841234567" not in blob
    assert "hunter2" not in blob


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_csv_export_no_raw_leaks(client: TestClient):
    _full_workflow(client)
    blob = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/evidence-summary.csv").text
    assert "9841234567" not in blob


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_json_no_overclaim(client: TestClient):
    _full_workflow(client)
    blob = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").text.lower()
    assert not any(p in blob for p in OVERCLAIM_PHRASES)


@pytest.mark.integration
@pytest.mark.usefixtures("seeded_db")
def test_final_json_no_raw_payload_field(client: TestClient):
    _full_workflow(client)
    body = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report.json").json()

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                assert k not in ("raw_payload", "raw_value", "password_hash")
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(body)


def test_render_pdf_and_html_unit_minimal():
    report = FinalInvestigationReport(
        metadata=FinalReportMetadata(
            incident_id="INC-TEST",
            generated_at=datetime.now(timezone.utc),
            report_format="pdf",
        ),
        executive_summary=FinalReportExecutiveSummary(
            human_review_status="pending — human review required",
            fix_verification_status="not completed — requires verification",
        ),
        incident=FinalReportIncidentSection(
            incident_id="INC-TEST",
            title="Test",
            status="open",
        ),
        guarded_explanation=FinalReportGuardedExplanation(
            not_generated_message="Guarded explanation was not generated for this incident.",
        ),
        human_review=FinalReportHumanReview(
            not_completed_message="Human review has not yet been completed.",
        ),
        fix_verification=FinalReportFixVerification(
            not_completed_message="Fix verification has not yet been completed.",
        ),
    )
    pdf = final_report_pdf_service.render_final_report_pdf(report)
    assert pdf[:4] == b"%PDF"
    html_doc = final_report_service.render_final_report_html(report)
    assert "Final Investigation Report" in html_doc
