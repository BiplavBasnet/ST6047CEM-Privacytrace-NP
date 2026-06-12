"""Phase K: durable `integration_events` persistence (see docs/LIVE_CORRELATION_MODEL.md).

`siem_import_service._INTEGRATION_EVENT_STORE` is a read-through cache only;
the `integration_events` table is the source of truth `get_event_record`
falls back to on a cache miss. These tests ingest an event, clear the
in-memory cache (simulating a process restart), and prove
`GET /integrations/events/{id}` still resolves from the database.
"""

from __future__ import annotations

import pytest

from app.dependencies import get_db_session
from app.main import app
from app.services import siem_import_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

EVENT_PAYLOAD = {
    "source_name": "wallet-service",
    "source_type": "api_log",
    "source_format": "generic_json",
    "environment": "staging",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "event_time": "2026-07-13T10:30:00Z",
    "severity": "info",
    "message": "Synthetic application health event",
    "metadata": {
        "deployment_version": "v1.4.2",
        "trace_id": "trace-persist-001",
    },
}


@pytest.fixture(autouse=True)
def gateway_db_override(db_session):
    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    siem_import_service.clear_event_store()
    yield
    siem_import_service.clear_event_store()
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _analyst_token(client, demo_users, db_session) -> str:
    db_session.commit()
    return login(client, email="analyst@privacytrace.local", password="AnalystPass123!")


def test_event_readable_after_clearing_in_memory_store(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)

    ingest = client_no_auth_override.post(
        "/integrations/events", headers=headers, json=EVENT_PAYLOAD
    )
    assert ingest.status_code == 200, ingest.text
    integration_event_id = ingest.json()["integration_event_id"]
    assert integration_event_id

    # Sanity: readable via the still-warm in-memory cache.
    warm = client_no_auth_override.get(
        f"/integrations/events/{integration_event_id}", headers=headers
    )
    assert warm.status_code == 200, warm.text

    # Simulate a process restart by dropping the in-memory cache only. The
    # durable `integration_events` row is what `get_event_record` should now
    # fall back to.
    siem_import_service.clear_event_store()

    cold = client_no_auth_override.get(
        f"/integrations/events/{integration_event_id}", headers=headers
    )
    assert cold.status_code == 200, cold.text
    cold_body = cold.json()
    assert cold_body["integration_event_id"] == integration_event_id
    assert cold_body["service_name"] == "wallet-service"
    assert cold_body["endpoint"] == "/wallet/transfer"
    assert cold_body["message_summary"]
    assert cold_body["safety_status"] == "safe"


def test_correlation_keys_survive_cache_clear(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)

    ingest = client_no_auth_override.post(
        "/integrations/events", headers=headers, json=EVENT_PAYLOAD
    )
    assert ingest.status_code == 200, ingest.text
    integration_event_id = ingest.json()["integration_event_id"]

    siem_import_service.clear_event_store()

    cold = client_no_auth_override.get(
        f"/integrations/events/{integration_event_id}", headers=headers
    )
    assert cold.status_code == 200, cold.text
    correlation_keys = cold.json()["correlation_keys"]
    assert correlation_keys.get("deployment_version") == "v1.4.2"
    assert "trace_id" not in correlation_keys


def test_unknown_event_id_returns_404_after_cache_clear(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)
    siem_import_service.clear_event_store()

    response = client_no_auth_override.get(
        "/integrations/events/INT-EVT-DOES-NOT-EXIST", headers=headers
    )
    assert response.status_code == 404
