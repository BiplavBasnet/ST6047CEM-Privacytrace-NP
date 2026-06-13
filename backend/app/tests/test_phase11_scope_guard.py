"""Phase 11 scope guard — dashboard allowed; backend business logic unchanged."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FRONTEND = PROJECT_ROOT / "frontend"
BACKEND_APP = PROJECT_ROOT / "backend" / "app"


def test_phase11_frontend_exists():
    assert (FRONTEND / "package.json").is_file()
    assert (FRONTEND / "PHASE11_SCOPE.md").is_file()
    assert (FRONTEND / "src" / "utils" / "safety.ts").is_file()
    assert (FRONTEND / "src" / "api" / "client.ts").is_file()


def test_phase11_cors_middleware_in_main():
    main_py = (BACKEND_APP / "main.py").read_text(encoding="utf-8")
    assert "CORSMiddleware" in main_py
    assert "http://127.0.0.1:5173" in main_py
    assert "Phase 11" in main_py or "phase 11" in main_py.lower()


def test_no_phase12_deployment_artifacts():
    forbidden = (
        PROJECT_ROOT / "DEPLOYMENT.md",
        PROJECT_ROOT / "docs" / "phase12_deployment.md",
        PROJECT_ROOT / "kubernetes",
    )
    for path in forbidden:
        assert not path.exists(), f"Phase 12 artifact present: {path}"


def test_no_new_core_business_modules_in_phase11():
    """Static guard: no new detection/LLM/scanner modules added for Phase 11."""
    services = BACKEND_APP / "services"
    forbidden_names = (
        "cloud_llm",
        "openai",
        "finetune",
        "fine_tune",
        "scanner_engine",
        "new_detector",
    )
    for py_file in services.rglob("*.py"):
        name_lower = py_file.name.lower()
        if any(token in name_lower for token in forbidden_names):
            raise AssertionError(f"Unexpected service module: {py_file}")


def test_phase11_frontend_has_safety_tests():
    tests_dir = FRONTEND / "src" / "__tests__"
    assert (tests_dir / "safety.test.ts").is_file()
