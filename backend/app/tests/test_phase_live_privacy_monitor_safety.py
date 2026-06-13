from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.models.privacy_alert import PrivacyAlert
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

BASE_EVENT = {
    "source_type": "api_log",
    "source_name": "wallet-service",
    "source_format": "generic_json",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "environment": "demo",
    "timestamp": "2026-05-20T10:15:00Z",
    "message": "placeholder",
    "metadata": {"release_version": "v1.2.0"},
}


@pytest.fixture(autouse=True)
def override_db_session_for_live_monitor_safety(db_session):
    from app.dependencies import get_db_session
    from app.main import app

    def _override():
        yield db_session

    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture
def demo_users(db_session):
    return seed_demo_users_in_db(db_session)


@pytest.fixture
def client_no_auth_override(client):
    from app.dependencies.auth_dependencies import get_current_user
    from app.main import app

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _analyst_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(client_no_auth_override, email="analyst@privacytrace.local", password="AnalystPass123!")


SENSITIVE_CASES = [
    # `sensitive_type` values are the unified exposure engine's canonical
    # taxonomy names (`sensitive_data_taxonomy_service`), not the legacy
    # regex-rule names the detector still uses internally as pattern ids
    # (e.g. "wallet_id" -> "wallet_identifier", "jwt_token" -> "jwt",
    # "authorization_header" -> "bearer_token"). Masked previews now come
    # from the one shared `masking_service.mask_value`/`masking_rules.yaml`
    # table (keyed by the internal pattern id) for both Live Monitor and
    # Evidence, rather than Live Monitor's own former regex-based masking
    # (which used different prefix/suffix lengths and label text).
    ("Synthetic phone 9841234567 copied into log", "9841234567", "98******67", "phone_number"),
    ("Wallet WALLET-NP-88291 copied into log", "WALLET-NP-88291", "wallet_[masked]", "wallet_identifier"),
    ("Transaction TXN-NP-2026-77881 copied into log", "TXN-NP-2026-77881", "txn_[masked]", "transaction_reference"),
    ("Token eyJhbGciOiJIUzI1NiJ9.payload.signature copied into log", "eyJhbGciOiJIUzI1NiJ9.payload.signature", "jwt_[masked]", "jwt"),
    ("Auth Bearer abcdefghijklmnop copied into log", "Bearer abcdefghijklmnop", "bearer_[masked]", "bearer_token"),
    ("Authorization: Bearer abcdefghijklmnop", "Authorization: Bearer abcdefghijklmnop", "authorization_[masked]", "bearer_token"),
    ("API key pk_test_np_fake_12345 copied into log", "pk_test_np_fake_12345", "key_[masked]", "api_key"),
    ("API key sk-abcdefghijklmnopqrstuvwxyz123456 copied into log", "sk-abcdefghijklmnopqrstuvwxyz123456", "key_[masked]", "api_key"),
    ("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "private_key_[masked]", "private_key"),
    ("password=secret", "password=secret", "password_[masked]", "password"),
    (r'DeviceConfig="{\"mqtt\":{\"password\":\"supersecret\"}}"', "supersecret", "password_[masked]", "password"),
    (r'DeviceConfig="{\"mqtt\":{\"name\":\"sptmqttadmin\",\"password\":\"supersecret\"}}"', "sptmqttadmin", "username_[masked]", "credential_username"),
    (r'{"accessToken":"opaque-access-token-123456"}', "opaque-access-token-123456", "token_[masked]", "access_token"),
    ("session_token=abc123xyz", "session_token=abc123xyz", "session_[masked]", "session_token"),
]


@pytest.mark.parametrize("message,raw,masked,sensitive_type", SENSITIVE_CASES)
def test_sensitive_live_events_return_masked_alert_only(client_no_auth_override, demo_users, db_session, message, raw, masked, sensitive_type):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={**BASE_EVENT, "message": message},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    blob = json.dumps(body)
    assert body["status"] == "alert_created"
    assert sensitive_type in body["sensitive_types"]
    assert masked in blob
    assert raw not in blob


def test_alert_stores_hash_and_masked_values_but_not_raw_event(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={**BASE_EVENT, "message": "Synthetic phone 9841234567 copied into log"},
    )
    assert response.status_code == 200
    alert_id = response.json()["alert_id"]
    alert = db_session.scalar(select(PrivacyAlert).where(PrivacyAlert.alert_id == alert_id))
    assert alert is not None
    assert alert.raw_event_hash.startswith("sha256:")
    assert "98******67" in alert.masked_values
    serialized = json.dumps({"summary": alert.alert_summary, "values": alert.masked_values})
    assert "9841234567" not in serialized


@pytest.mark.parametrize("field", ["metadata", "payload"])
def test_nested_live_event_content_is_scanned_and_never_returned(
    client_no_auth_override, demo_users, db_session, field
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    event = {**BASE_EVENT, "message": "Structured event received"}
    event[field] = {"device_config": {"password": "nested-secret-value"}}
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json=event,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "alert_created"
    assert "password" in body["sensitive_types"]
    assert "nested-secret-value" not in json.dumps(body)


def test_alert_list_and_detail_return_masked_values_only(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    created = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={**BASE_EVENT, "message": "Wallet WALLET-NP-88291 copied into log"},
    )
    alert_id = created.json()["alert_id"]
    listing = client_no_auth_override.get("/live-monitor/alerts", headers=auth_headers(token))
    detail = client_no_auth_override.get(f"/live-monitor/alerts/{alert_id}", headers=auth_headers(token))
    assert listing.status_code == 200
    assert detail.status_code == 200
    for body in (listing.json(), detail.json()):
        blob = json.dumps(body)
        assert "wallet_[masked]" in blob
        assert "WALLET-NP-88291" not in blob
        assert "raw_message" not in blob
        assert "raw_event_content" not in blob


def test_unsafe_error_does_not_echo_raw_value(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={**BASE_EVENT, "source_format": "unknown", "message": "Synthetic phone 9841234567 copied into log"},
    )
    assert response.status_code == 400
    assert "9841234567" not in response.text


def test_narrative_wording_alone_is_accepted_as_input_evidence(client_no_auth_override, demo_users, db_session):
    """Phase P: ingested event text is not rejected for certainty/blame
    wording alone (it may be an attributed quote from the source system).
    Only raw secrets/sensitive values trigger masking or rejection."""
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={**BASE_EVENT, "message": "This is the proven cause of the issue"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["safety_status"] == "safe"
    assert body["status"] == "no_alert"


def test_narrative_wording_with_sensitive_value_is_masked_not_rejected(
    client_no_auth_override, demo_users, db_session
):
    """A source-attributed overclaim quote alongside a real sensitive value
    is still ingested; the sensitive value is masked, the wording is kept."""
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={
            **BASE_EVENT,
            "message": "Ticket notes: attacker accessed data, phone 9841234567 copied into log",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "alert_created"
    assert "9841234567" not in json.dumps(body)


def test_live_monitor_response_contains_no_forbidden_wording(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/live-monitor/events",
        headers=auth_headers(token),
        json={**BASE_EVENT, "message": "Synthetic phone 9841234567 copied into log"},
    )
    blob = json.dumps(response.json()).lower()
    for phrase in (
        "proven cause",
        "confirmed blame",
        "guaranteed cause",
        "guaranteed fixed",
        "confirmed bola",
        "confirmed idor",
        "attacker accessed data",
        "works in any environment",
        "production certified",
        "siem replacement",
    ):
        assert phrase not in blob

