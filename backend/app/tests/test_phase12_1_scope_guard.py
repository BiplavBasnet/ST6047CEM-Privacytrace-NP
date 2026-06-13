"""Phase 12.1 scope guard — final report only, no full Phase 12 packaging."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.tests.route_test_utils import registered_routes

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FRONTEND_SRC = PROJECT_ROOT / "frontend" / "src"

BANNED_REPORT_PATTERNS = [
    re.compile(r"\bTruffleHog\b", re.I),
    re.compile(r"\bGitleaks Integration\b", re.I),
    re.compile(r"\bPowered by TruffleHog\b", re.I),
]

FINAL_REPORT_UI = [
    FRONTEND_SRC / "components" / "FinalReportExportPanel.tsx",
    FRONTEND_SRC / "components" / "ReportSafetyNotice.tsx",
]


def test_no_new_llm_provider_modules():
    backend = PROJECT_ROOT / "backend" / "app" / "services"
    assert not (backend / "openai_provider_service.py").exists()
    assert not (backend / "anthropic_provider_service.py").exists()


def test_no_phase12_packaging_artifacts():
    blocked = [
        PROJECT_ROOT / "docs" / "phase12_deployment.md",
        PROJECT_ROOT / "docs" / "PHASE12_FINAL_PACKAGING.md",
    ]
    for path in blocked:
        assert not path.exists(), f"Phase 12 packaging artifact present: {path}"


def test_final_report_routes_registered():
    from app.main import app

    paths = {route.path for route in registered_routes(app)}
    assert "/reports/incidents/{incident_id}/final-report.pdf" in paths
    assert "/reports/incidents/{incident_id}/final-report.html" in paths
    assert "/reports/incidents/{incident_id}/final-report.json" in paths
    assert "/reports/incidents/{incident_id}/evidence-summary.csv" in paths
    assert "/reports/incidents/{incident_id}/final-report-bundle.zip" in paths


def test_no_raw_report_export_route():
    from app.main import app

    for route in registered_routes(app):
        path = getattr(route, "path", "")
        assert "raw-report" not in path.lower()


def test_existing_generate_report_route_preserved():
    from app.main import app

    paths = {route.path for route in registered_routes(app)}
    assert "/reports/incidents/{incident_id}/generate" in paths


def test_health_endpoint_still_registered():
    from app.main import app

    paths = {route.path for route in registered_routes(app)}
    assert "/health" in paths


@pytest.mark.parametrize("ui_path", FINAL_REPORT_UI, ids=lambda p: p.name)
def test_final_report_ui_avoids_vendor_branding(ui_path: Path):
    if not ui_path.exists():
        pytest.skip(f"{ui_path.name} not created yet")
    text = ui_path.read_text(encoding="utf-8")
    for pattern in BANNED_REPORT_PATTERNS:
        assert not pattern.search(text), pattern.pattern


def test_final_report_service_files_exist():
    services = PROJECT_ROOT / "backend" / "app" / "services"
    assert (services / "final_report_service.py").exists()
    assert (services / "final_report_pdf_service.py").exists()
    assert (services / "final_report_bundle_service.py").exists()
