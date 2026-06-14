"""Acceptance coverage for the Universal Integration Gateway."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select

from app.dependencies import get_db_session
from app.main import app
from app.models.audit_log import AuditLog
from app.models.incident import Incident
from app.models.integration_token import IntegrationToken
from app.models.normalized_event import NormalizedEvent
from app.models.privacy_alert import PrivacyAlert
from app.services import siem_import_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

SAFE_EVENT = {
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
        "trace_id": "trace-demo-001",
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
    return login(
        client,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )


def _admin_token(client, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client,
        email="admin@privacytrace.local",
        password="AdminPass123!",
    )


def test_gateway_discovery_endpoints_return_safe_contract(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)

    status_response = client_no_auth_override.get(
        "/integrations/status", headers=headers
    )
    assert status_response.status_code == 200, status_response.text
    gateway_status = status_response.json()
    assert gateway_status["gateway_enabled"] is True
    assert "api_log" in gateway_status["accepted_event_types"]
    assert gateway_status["safety_status"] == "safe"

    schema_response = client_no_auth_override.get(
        "/integrations/schema", headers=headers
    )
    assert schema_response.status_code == 200
    schema = schema_response.json()
    assert schema["endpoint"] == "/integrations/events"
    assert {"source_name", "message"} <= set(schema["required_fields"])
    assert "custom" in schema["accepted_source_types"]

    snippets_response = client_no_auth_override.get(
        "/integrations/snippets", headers=headers
    )
    assert snippets_response.status_code == 200
    snippets = snippets_response.json()
    assert "/integrations/events" in snippets["curl"]
    assert "requests.post" in snippets["python"]
    assert "fetch(" in snippets["node"]
    assert "docker build" in snippets["docker_log_forwarder"]
    assert "9812345678" not in json.dumps(snippets)


def test_safe_event_is_normalized_without_creating_alert(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=SAFE_EVENT,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["alert_created"] is False
    assert body["event"]["source_type"] == "api_log"
    assert body["event"]["correlation_strength"] == "strong"
    assert body["event"]["raw_payload_hash"].startswith("sha256:")
    assert db_session.scalar(select(func.count(NormalizedEvent.id))) == 1
    assert db_session.scalar(select(func.count(PrivacyAlert.id))) == 0


def test_validation_masks_preview_and_does_not_store_event(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    before = db_session.scalar(select(func.count(NormalizedEvent.id))) or 0
    raw_phone = "9841234567"
    response = client_no_auth_override.post(
        "/integrations/validate",
        headers=auth_headers(token),
        json={
            **SAFE_EVENT,
            "message": f"Synthetic phone={raw_phone} appeared in a log",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is True
    assert body["would_create_alert"] is True
    assert raw_phone not in json.dumps(body)
    after = db_session.scalar(select(func.count(NormalizedEvent.id))) or 0
    assert after == before


def test_leak_event_creates_masked_live_alert_and_incident(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    raw_phone = "9841234567"
    raw_wallet = "WALLET-NP-88291"
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json={
            **SAFE_EVENT,
            "message": (
                f"Synthetic log phone={raw_phone} wallet={raw_wallet}"
            ),
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    serialized = json.dumps(body)
    assert body["alert_created"] is True
    assert raw_phone not in serialized
    assert raw_wallet not in serialized

    alert_response = client_no_auth_override.get(
        f"/live-monitor/alerts/{body['alert_id']}",
        headers=auth_headers(token),
    )
    assert alert_response.status_code == 200, alert_response.text
    alert = alert_response.json()
    assert alert["ingestion_source"] == "integration_gateway"
    assert alert["source_name"] == SAFE_EVENT["source_name"]
    assert alert["evidence_strength"] == "strong"
    assert raw_phone not in json.dumps(alert)
    assert raw_wallet not in json.dumps(alert)

    incident_response = client_no_auth_override.post(
        f"/live-monitor/alerts/{body['alert_id']}/create-incident",
        headers=auth_headers(token),
        json={"mode": "create_new"},
    )
    assert incident_response.status_code == 200, incident_response.text
    incident_id = incident_response.json()["incident_id"]
    incident = db_session.scalar(
        select(Incident).where(Incident.incident_id == incident_id)
    )
    assert incident is not None
    assert incident.status.value == "new"


def test_missing_metadata_is_accepted_with_limited_correlation_advice(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json={
            "source_name": "custom-source",
            "source_type": "unlisted_type",
            "message": "Synthetic event with intentionally sparse metadata",
        },
    )
    assert response.status_code == 200, response.text
    event = response.json()["event"]
    assert event["source_type"] == "custom"
    assert event["correlation_strength"] == "limited"
    assert {"service_name", "endpoint", "event_time"} <= set(
        event["missing_metadata"]
    )
    assert any("service_name" in item for item in event["recommendations"])
    assert any("endpoint" in item for item in event["recommendations"])
    assert "custom" in event["warning"].lower()


def test_missing_required_fields_are_reported_without_echo(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    raw_phone = "9841234567"
    payload = {"message": f"Synthetic phone={raw_phone}"}

    response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(token),
        json=payload,
    )
    assert response.status_code == 422
    assert "source_name" in response.json()["detail"]["required_fields_missing"]
    assert raw_phone not in response.text

    validation = client_no_auth_override.post(
        "/integrations/validate",
        headers=auth_headers(token),
        json=payload,
    )
    assert validation.status_code == 200
    body = validation.json()
    assert body["valid"] is False
    assert body["required_fields_missing"] == ["source_name"]
    assert raw_phone not in validation.text


def test_batch_returns_safe_per_item_results(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    raw_phone = "9841234567"
    response = client_no_auth_override.post(
        "/integrations/events/batch",
        headers=auth_headers(token),
        json={
            "events": [
                SAFE_EVENT,
                {
                    **SAFE_EVENT,
                    "message": f"Synthetic phone={raw_phone}",
                },
                {"message": "Missing source"},
            ]
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3
    assert body["accepted"] == 2
    assert body["rejected"] == 1
    assert body["results"][1]["alert_created"] is True
    assert body["results"][2]["reason"] == "Event validation failed."
    assert raw_phone not in json.dumps(body)


def test_integration_token_is_ingestion_only_revocable_and_never_logged(
    client_no_auth_override, demo_users, db_session
):
    admin_token = _admin_token(client_no_auth_override, demo_users, db_session)
    admin_headers = auth_headers(admin_token)
    created_response = client_no_auth_override.post(
        "/integrations/tokens",
        headers=admin_headers,
        json={"name": "Test forwarder", "source_name": "token-bound-source"},
    )
    assert created_response.status_code == 200, created_response.text
    created = created_response.json()
    raw_token = created["token"]
    token_id = created["token_id"]
    assert raw_token.startswith("ptig_")

    record = db_session.scalar(
        select(IntegrationToken).where(IntegrationToken.token_id == token_id)
    )
    assert record is not None
    assert record.token_hash != raw_token
    assert raw_token not in record.token_hash

    ingest_response = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(raw_token),
        json={**SAFE_EVENT, "source_name": "spoofed-source"},
    )
    assert ingest_response.status_code == 200, ingest_response.text
    assert ingest_response.json()["event"]["source_name"] == "token-bound-source"

    denied_read = client_no_auth_override.get(
        "/integrations/status", headers=auth_headers(raw_token)
    )
    assert denied_read.status_code in (401, 403)

    listed = client_no_auth_override.get(
        "/integrations/tokens", headers=admin_headers
    )
    assert listed.status_code == 200
    assert "token" not in listed.json()["tokens"][0]
    assert raw_token not in listed.text

    revoked = client_no_auth_override.delete(
        f"/integrations/tokens/{token_id}", headers=admin_headers
    )
    assert revoked.status_code == 200
    assert revoked.json()["is_active"] is False
    rejected = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers(raw_token),
        json=SAFE_EVENT,
    )
    assert rejected.status_code == 401

    audits = db_session.scalars(select(AuditLog)).all()
    assert raw_token not in json.dumps(
        [
            {
                "action": item.action,
                "target": item.target_id,
                "details": item.details,
            }
            for item in audits
        ],
        default=str,
    )


def test_wrong_or_missing_integration_token_is_rejected(client_no_auth_override):
    missing = client_no_auth_override.post(
        "/integrations/events", json=SAFE_EVENT
    )
    assert missing.status_code == 401
    wrong = client_no_auth_override.post(
        "/integrations/events",
        headers=auth_headers("ptig_" + "x" * 40),
        json=SAFE_EVENT,
    )
    assert wrong.status_code == 401
    assert "x" * 40 not in wrong.text


def test_synthetic_gateway_test_event_updates_health(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/integrations/test-event", headers=auth_headers(token)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["alert_created"] is True
    assert "9841234567" not in response.text

    status_response = client_no_auth_override.get(
        "/integrations/status", headers=auth_headers(token)
    )
    health = status_response.json()
    assert health["events_received_count"] == 1
    assert health["alerts_created_count"] == 1
    assert health["source_name"] == "integration-hub-test"
