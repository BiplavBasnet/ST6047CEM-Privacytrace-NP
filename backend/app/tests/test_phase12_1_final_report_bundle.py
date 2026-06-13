"""Phase 12.1 — final report ZIP bundle."""

from __future__ import annotations

import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from app.db.seed_phase2 import SEED_INCIDENT_ID
from app.tests.test_phase10_reports_metrics import _full_workflow

pytestmark = pytest.mark.usefixtures("seeded_db")


@pytest.mark.integration
def test_zip_endpoint_content_type(client: TestClient):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report-bundle.zip")
    assert response.status_code == 200, response.text
    assert "zip" in response.headers.get("content-type", "")


@pytest.mark.integration
def test_zip_contains_required_files(client: TestClient):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report-bundle.zip")
    with zipfile.ZipFile(BytesIO(response.content)) as zf:
        names = set(zf.namelist())
    assert "final_investigation_report.pdf" in names
    assert "final_investigation_report.html" in names
    assert "final_investigation_report.json" in names
    assert "evidence_summary.csv" in names
    assert "README.txt" in names


@pytest.mark.integration
def test_zip_no_raw_evidence_files(client: TestClient):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report-bundle.zip")
    with zipfile.ZipFile(BytesIO(response.content)) as zf:
        for name in zf.namelist():
            assert not name.endswith(".log")
            assert not name.startswith("evidence_files/")
            assert "raw" not in name.lower()


@pytest.mark.integration
def test_zip_readme_privacy_explanation(client: TestClient):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report-bundle.zip")
    with zipfile.ZipFile(BytesIO(response.content)) as zf:
        readme = zf.read("README.txt").decode("utf-8")
    assert "privacy" in readme.lower()
    assert "human review" in readme.lower()
    assert "does not prove blame" in readme.lower()


@pytest.mark.integration
def test_zip_json_inside_has_no_raw_payload_key(client: TestClient):
    _full_workflow(client)
    response = client.get(f"/reports/incidents/{SEED_INCIDENT_ID}/final-report-bundle.zip")
    with zipfile.ZipFile(BytesIO(response.content)) as zf:
        inner = zf.read("final_investigation_report.json").decode("utf-8")
    assert "raw_payload" not in inner
    assert "9841234567" not in inner
