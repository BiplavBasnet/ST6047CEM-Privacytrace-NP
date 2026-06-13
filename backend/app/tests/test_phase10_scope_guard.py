"""Phase 10 scope guard — no dashboard, frontend, Phase 11, or cloud LLM creep."""

from __future__ import annotations

from pathlib import Path

from app.main import app
from app.tests.route_test_utils import registered_routes

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_no_unauthorized_dashboard_directories_added():
  """Phase 11 allows frontend/; still block ad-hoc dashboard clones."""
  forbidden_dirs = (
      PROJECT_ROOT / "dashboard",
      PROJECT_ROOT / "web",
      PROJECT_ROOT / "client",
  )
  for path in forbidden_dirs:
      assert not path.is_dir(), f"Scope creep: directory added at {path}"


def test_no_react_package_files_at_project_root():
  markers = ("package.json", "vite.config.ts", "next.config.js")
  for name in markers:
      assert not (PROJECT_ROOT / name).exists(), f"Scope creep: {name} at project root"


def test_no_phase11_routes():
  paths = [getattr(r, "path", "") for r in registered_routes(app)]
  for fragment in ("/phase11", "/dashboard", "/ui/"):
      assert not any(fragment in p for p in paths), f"Forbidden route fragment: {fragment}"


def test_no_cloud_llm_provider_modules():
  backend = PROJECT_ROOT / "backend" / "app"
  forbidden_snippets = (
      "openai.com",
      "anthropic.com",
      "azure_openai",
      "bedrock",
      "finetune",
      "fine_tune",
      "fine-tune",
  )
  for py_file in backend.rglob("*.py"):
      if "test_" in py_file.name or py_file.name == "__init__.py":
          continue
      text = py_file.read_text(encoding="utf-8", errors="ignore").lower()
      for snippet in forbidden_snippets:
          assert snippet not in text, f"Scope creep in {py_file}: {snippet}"


def test_phase10_report_and_metrics_routes_exist():
  paths = [getattr(r, "path", "") for r in registered_routes(app)]
  assert any("/reports/incidents/{incident_id}/generate" in p for p in paths)
  assert any("/reports/incidents/{incident_id}" in p for p in paths)
  assert any(p.endswith("/metrics/evaluation") or "/metrics/evaluation" in p for p in paths)
  assert any("/metrics/evaluation/run" in p for p in paths)


def test_no_unrelated_product_endpoints():
  paths = [getattr(r, "path", "") for r in registered_routes(app)]
  for forbidden in ("/signup", "/widgets", "/chart-data"):
      assert not any(forbidden in p for p in paths)
  # Phase 11.6 uses /auth/login; block only a standalone product login route.
  assert not any(p == "/login" for p in paths)
