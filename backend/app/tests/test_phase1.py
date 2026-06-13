"""Phase 1 acceptance tests: imports, configuration, and health endpoint."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def test_backend_app_imports_successfully():
    """Core application modules import without errors."""
    from app.config import Settings, get_settings
    from app.database import Base, SessionLocal, check_database_connection, engine, get_db
    from app.main import app
    from app.routers import health_router

    assert app.title == "PrivacyTrace-NP"
    assert app.version == "0.1.0"
    assert health_router.router is not None
    assert get_settings is not None
    assert Settings is not None
    assert engine is not None
    assert SessionLocal is not None
    assert Base is not None
    assert callable(get_db)
    assert callable(check_database_connection)


def test_database_connection_configuration_loads():
    """Settings and SQLAlchemy engine use a valid PostgreSQL DATABASE_URL."""
    from app.config import get_settings
    from app.database import engine

    settings = get_settings()

    assert settings.database_url.startswith("postgresql://")
    expected_app_env = "test" if os.getenv("REQUIRE_TEST_POSTGRES") == "1" else "development"
    assert settings.app_env == expected_app_env
    assert settings.service_name == "privacytrace-np"

    engine_url = str(engine.url)
    assert engine_url.startswith("postgresql")
    if os.getenv("REQUIRE_TEST_POSTGRES") == "1":
        from app.tests.conftest import _require_dedicated_test_postgres

        _require_dedicated_test_postgres()


def test_health_endpoint_returns_success(client: TestClient):
    """GET /health returns 200 with healthy status when database is reachable."""
    with patch("app.routers.health_router.check_database_connection", return_value=True):
        response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "privacytrace-np"
    assert data["database"] == "connected"
    assert data["version"] == "0.1.0"


@pytest.mark.integration
def test_health_endpoint_with_live_database(client: TestClient):
    """GET /health succeeds against a running PostgreSQL instance (optional)."""
    from app.database import check_database_connection

    if not check_database_connection():
        pytest.skip("PostgreSQL is not running; start with: docker compose up -d")

    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
