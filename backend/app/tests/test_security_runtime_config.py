"""Runtime security configuration guardrail tests."""

import pytest

from app.config import get_settings, validate_runtime_configuration


def test_development_defaults_are_allowed_for_local_demo(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    get_settings.cache_clear()
    validate_runtime_configuration(get_settings())
    get_settings.cache_clear()


def test_production_rejects_demo_secrets(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://privacytrace:privacytrace_dev@localhost:5432/privacytrace_np",
    )
    monkeypatch.setenv("JWT_PRIVATE_KEY_PATH", "")
    monkeypatch.setenv("JWT_PUBLIC_KEY_PATH", "")
    monkeypatch.setenv("DATA_KEY_PRIVATE_KEY_PATH", "")
    monkeypatch.setenv("DATA_KEY_PUBLIC_KEY_PATH", "")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError) as excinfo:
        validate_runtime_configuration(get_settings())
    message = str(excinfo.value)
    assert "development fallback secret" in message
    assert "development database password" in message
    assert "privacytrace-np-dev-secret-change-in-production" not in message
    get_settings.cache_clear()


def test_production_rejects_known_bootstrap_default(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql://privacytrace:prod_secret@localhost:5432/privacytrace_np")
    monkeypatch.setenv("JWT_SECRET_KEY", "production-jwt-secret-not-for-demo")
    monkeypatch.setenv("JWT_PRIVATE_KEY_PATH", "")
    monkeypatch.setenv("JWT_PUBLIC_KEY_PATH", "")
    monkeypatch.setenv("CRYPTO_ENCRYPTION_ENABLED", "false")
    monkeypatch.setenv("COMPANY_VERIFICATION_MODE", "manual")
    monkeypatch.setenv("SEED_DEMO_USERS", "false")
    monkeypatch.setenv("BREACH_ALERTS_ENABLED", "false")
    monkeypatch.setenv("NEPAL_FINANCIAL_TAXONOMY_ENABLED", "false")
    monkeypatch.setenv("AI_ASSISTANT_ENABLED", "false")
    monkeypatch.setenv("PRIVACYTRACE_BOOTSTRAP_TOKEN", "dev-bootstrap-change-me")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError) as excinfo:
        validate_runtime_configuration(get_settings())
    message = str(excinfo.value)
    assert "PRIVACYTRACE_BOOTSTRAP_TOKEN uses the development fallback secret" in message
    assert "dev-bootstrap-change-me" not in message
    get_settings.cache_clear()
