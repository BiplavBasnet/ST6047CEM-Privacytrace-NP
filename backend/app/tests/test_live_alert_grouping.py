"""Phase I: real alert grouping (see docs/LIVE_ALERT_GROUPING.md).

Before this phase every accepted Live Monitor event created a brand-new
`PrivacyAlert`, and `first_seen`/`last_seen`/`repeat_count` on the API
response were hardcoded to `alert_time`/`alert_time`/`1`. These tests exercise
the real `live_alert_grouping_service` behaviour through the HTTP endpoint:
recurrences of the same underlying exposure attach to one alert lineage, and
unrelated exposures (different service, different sensitive type) each get
their own alert.
"""

from __future__ import annotations

import pytest

from app.dependencies import get_db_session
from app.main import app
from app.services import live_alert_grouping_service
from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db", "running_live_monitor")

BASE_EVENT = {
    "source_type": "api_log",
    "source_name": "wallet-service",
    "source_format": "generic_json",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "environment": "demo",
    "metadata": {},
}


@pytest.fixture(autouse=True)
def override_db_session(db_session):
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

    app.dependency_overrides.pop(get_current_user, None)
    yield client
    app.dependency_overrides.pop(get_current_user, None)


def _analyst_token(client_no_auth_override, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client_no_auth_override, email="analyst@privacytrace.local", password="AnalystPass123!"
    )


def test_compute_group_key_is_deterministic_and_order_sensitive_to_dimensions():
    key_a = live_alert_grouping_service.compute_group_key(
        sensitive_type="phone_number",
        exposure_location="application_log",
        service="wallet-service",
        endpoint="/wallet/transfer",
        environment="demo",
    )
    key_b = live_alert_grouping_service.compute_group_key(
        sensitive_type="phone_number",
        exposure_location="application_log",
        service="wallet-service",
        endpoint="/wallet/transfer",
        environment="demo",
    )
    key_different_service = live_alert_grouping_service.compute_group_key(
        sensitive_type="phone_number",
        exposure_location="application_log",
        service="auth-service",
        endpoint="/wallet/transfer",
        environment="demo",
    )
    assert key_a == key_b
    assert key_a != key_different_service
    assert key_a.startswith("AGRP-")


def test_repeated_exposure_increments_repeat_count_and_keeps_first_seen(
    client_no_auth_override, demo_users, db_session,
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)
    first = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:00:00Z",
            "message": "Synthetic phone 9841234567 copied into log",
        },
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["status"] == "alert_created"
    first_alert_id = first_body["alert_id"]
    assert first_body["alert"]["repeat_count"] == 1
    first_seen = first_body["alert"]["first_seen"]
    assert first_body["alert"]["last_seen"] == first_seen

    second = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:05:00Z",
            "message": "Synthetic phone 9841234567 copied into log again",
        },
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["status"] == "alert_created"

    # Same underlying exposure (same type/location/service/endpoint/env)
    # recorded as a recurrence on the same alert lineage, not a new alert.
    assert second_body["alert_id"] == first_alert_id
    assert second_body["alert"]["repeat_count"] == 2
    assert second_body["alert"]["first_seen"] == first_seen
    assert second_body["alert"]["last_seen"] != first_seen

    third = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:10:00Z",
            "message": "Synthetic phone 9841234567 copied into log once more",
        },
    )
    assert third.status_code == 200
    third_body = third.json()
    assert third_body["alert_id"] == first_alert_id
    assert third_body["alert"]["repeat_count"] == 3
    assert third_body["alert"]["first_seen"] == first_seen


def test_unrelated_service_does_not_join_the_group(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)
    first = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:00:00Z",
            "message": "Synthetic phone 9841234567 copied into log",
        },
    )
    assert first.status_code == 200
    first_alert_id = first.json()["alert_id"]

    second = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "service_name": "auth-service",
            "endpoint": "/auth/login",
            "timestamp": "2026-05-20T10:01:00Z",
            "message": "Synthetic phone 9841234567 copied into log",
        },
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["status"] == "alert_created"
    assert second_body["alert_id"] != first_alert_id
    assert second_body["alert"]["repeat_count"] == 1


def test_unrelated_sensitive_type_does_not_join_the_group(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)
    first = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:00:00Z",
            "message": "Synthetic phone 9841234567 copied into log",
        },
    )
    assert first.status_code == 200
    first_alert_id = first.json()["alert_id"]

    second = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:01:00Z",
            "message": "Wallet WALLET-NP-88291 copied into log",
        },
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["status"] == "alert_created"
    assert second_body["alert_id"] != first_alert_id


def test_dismissed_alert_does_not_absorb_new_recurrences(client_no_auth_override, demo_users, db_session):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    headers = auth_headers(token)
    first = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:00:00Z",
            "message": "Synthetic phone 9841234567 copied into log",
        },
    )
    assert first.status_code == 200
    first_alert_id = first.json()["alert_id"]

    dismiss = client_no_auth_override.post(
        f"/live-monitor/alerts/{first_alert_id}/dismiss",
        headers=headers,
        json={"reason": "Confirmed synthetic test fixture, not a real exposure."},
    )
    assert dismiss.status_code == 200, dismiss.text

    second = client_no_auth_override.post(
        "/live-monitor/events",
        headers=headers,
        json={
            **BASE_EVENT,
            "timestamp": "2026-05-20T10:05:00Z",
            "message": "Synthetic phone 9841234567 copied into log",
        },
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["status"] == "alert_created"
    # A dismissed alert is a closed lineage; the same exposure recurring
    # afterwards must start a fresh alert rather than reopening it silently.
    assert second_body["alert_id"] != first_alert_id
    assert second_body["alert"]["repeat_count"] == 1
