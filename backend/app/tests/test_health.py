from unittest.mock import patch

from fastapi.testclient import TestClient


def test_health_returns_503_when_database_disconnected(client: TestClient):
    with patch("app.routers.health_router.check_database_connection", return_value=False):
        response = client.get("/health")

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "unhealthy"
    assert data["database"] == "disconnected"