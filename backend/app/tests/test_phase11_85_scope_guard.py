"""Phase 11.85 scope guard: no vendor branding in UI, no raw_payload in API models."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FRONTEND_SRC = Path(__file__).resolve().parents[3] / "frontend" / "src"

BANNED_UI_PATTERNS = [
    re.compile(r"\bGitleaks\b", re.I),
    re.compile(r"\bSemgrep\b", re.I),
    re.compile(r"\bTruffleHog\b", re.I),
]

SCANNER_UI_PATHS = [
    FRONTEND_SRC / "pages" / "ScannerBridge.tsx",
    FRONTEND_SRC / "components" / "ScannerImportPanel.tsx",
    FRONTEND_SRC / "components" / "ScannerPreviewPanel.tsx",
    FRONTEND_SRC / "components" / "ScannerEvidenceTable.tsx",
    FRONTEND_SRC / "components" / "ScannerCorrelationPanel.tsx",
    FRONTEND_SRC / "components" / "ScannerSafetyRules.tsx",
    FRONTEND_SRC / "components" / "Layout.tsx",
    FRONTEND_SRC / "App.tsx",
]


def test_openapi_scanner_responses_exclude_raw_payload():
    from app.main import app

    schema = app.openapi()
    scanner_paths = {
        p: ops
        for p, ops in schema.get("paths", {}).items()
        if p.startswith("/scanner-bridge")
    }
    assert scanner_paths, "scanner-bridge routes must be registered"
    blob = str(scanner_paths).lower()
    assert "raw_payload" not in blob


@pytest.mark.parametrize("ui_path", SCANNER_UI_PATHS, ids=lambda p: p.name)
def test_scanner_ui_files_avoid_vendor_branding(ui_path: Path):
    if not ui_path.exists():
        pytest.skip(f"{ui_path.name} not created yet")
    text = ui_path.read_text(encoding="utf-8")
    for pattern in BANNED_UI_PATTERNS:
        assert not pattern.search(text), f"{pattern.pattern} found in {ui_path.name}"


def test_layout_nav_uses_scannerbridge_label():
    layout = FRONTEND_SRC / "components" / "Layout.tsx"
    if not layout.exists():
        pytest.skip("Layout not updated yet")
    text = layout.read_text(encoding="utf-8")
    assert "ScannerBridge-NP" in text or "scanner-bridge" in text


def test_phase11_8_integration_still_importable():
    import app.tests.test_phase11_8_universal_integration as mod

    assert hasattr(mod, "test_integration_routes_are_registered")
