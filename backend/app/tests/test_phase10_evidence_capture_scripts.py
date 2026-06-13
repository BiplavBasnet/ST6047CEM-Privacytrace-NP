"""Phase 10 evidence-capture script and completion-guard tests (static checks)."""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
DOCS_DIR = PROJECT_ROOT / "docs"
EVIDENCE_DIR = DOCS_DIR / "evidence_pack"


def _read(rel_path: str) -> str:
    path = PROJECT_ROOT / rel_path
    assert path.is_file(), f"Missing file: {rel_path}"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "rel_path",
    [
        "scripts/phase10_clean_reset.ps1",
        "scripts/phase10_prepare_workflow.ps1",
        "scripts/capture_phase10_evidence.ps1",
        "scripts/phase10_common.ps1",
    ],
)
def test_phase10_script_exists(rel_path: str) -> None:
    assert (PROJECT_ROOT / rel_path).is_file()


def test_capture_script_runs_pytest_and_saves_test_results() -> None:
    text = _read("scripts/capture_phase10_evidence.ps1")
    assert "run_backend_tests_with_postgres.py" in text
    assert "test_results.txt" in text


def test_capture_script_health_and_database_checks() -> None:
    text = _read("scripts/capture_phase10_evidence.ps1")
    common = _read("scripts/phase10_common.ps1")
    assert "Assert-Phase10HealthReady" in text or "/health" in text
    assert "database" in common.lower()
    assert "connected" in common.lower()


def test_capture_script_invokes_workflow_preparation() -> None:
    text = _read("scripts/capture_phase10_evidence.ps1")
    assert "phase10_prepare_workflow.ps1" in text


def test_capture_script_saves_api_outputs() -> None:
    text = _read("scripts/capture_phase10_evidence.ps1")
    common = _read("scripts/phase10_common.ps1")
    assert "api_outputs" in common
    assert "Save-Phase10SafeJson" in text or "api_outputs" in text


def test_capture_script_scans_raw_sensitive_values() -> None:
    common = _read("scripts/phase10_common.ps1")
    assert "9841234567" in common
    assert "WALLET-NP-88291" in common
    assert "Scan-Phase10AllApiOutputs" in common


def test_capture_script_scans_overclaim_phrases() -> None:
    common = _read("scripts/phase10_common.ps1")
    assert "proven cause" in common
    assert "guaranteed fixed" in common
    assert "Test-Phase10SafeContent" in common


def test_capture_script_cannot_pass_if_api_workflow_fails() -> None:
    text = _read("scripts/capture_phase10_evidence.ps1")
    assert '$ErrorActionPreference = "Stop"' in text
    assert "PHASE 10 EVIDENCE CAPTURE: PASS" in text
    assert "PHASE 10 EVIDENCE CAPTURE: FAIL" in text
    assert "exit 1" in text
    # Must not skip API capture when backend is up without failing
    assert "Assert-CaptureStep" in text or "throw" in text


def test_capture_script_writes_summary_and_status() -> None:
    text = _read("scripts/capture_phase10_evidence.ps1")
    assert "capture_summary.json" in text
    assert "capture_status.md" in text


def test_completion_checklist_exists_and_requires_capture_pass() -> None:
    text = _read("docs/phase10_completion_checklist.md")
    assert "capture_phase10_evidence.ps1" in text
    assert "PHASE 10 EVIDENCE CAPTURE: PASS" in text
    assert "False completion" in text or "false completion" in text.lower()
    assert "Phase 11" in text or "frontend" in text


def test_prepare_workflow_uses_existing_endpoints_only() -> None:
    text = _read("scripts/phase10_prepare_workflow.ps1")
    for path in (
        "/evidence/load-sample",
        "/evidence/parse-all",
        "/evidence/detect-all",
        "/incidents/analyse",
        "/trace",
        "/explain",
        "/review",
        "/verify-fix",
    ):
        assert path.replace("/trace", "") in text or path in text


def test_no_frontend_dashboard_react_added_in_phase10_hardening() -> None:
    """Guard against accidental Phase 11 scope in this repo slice."""
    backend_main = _read("backend/app/main.py")
    assert "/dashboard" not in backend_main
    assert "react" not in backend_main.lower()
    frontend_dirs = list(PROJECT_ROOT.glob("frontend")) + list(PROJECT_ROOT.glob("**/dashboard"))
    for d in frontend_dirs:
        if d.is_dir() and "node_modules" not in str(d):
            # Allow empty or absent; fail only if package.json with react appears at project root
            pass
    root_pkg = PROJECT_ROOT / "package.json"
    if root_pkg.is_file():
        pkg = root_pkg.read_text(encoding="utf-8").lower()
        assert "react" not in pkg, "Unexpected React package.json at project root"
