"""Phase 11.85 ScannerBridge safety boundary tests."""

from __future__ import annotations

import json

import pytest

from app.tests.auth_test_utils import auth_headers, login, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db")

SAFE_GITLEAKS = [
    {
        "RuleID": "generic-api-key",
        "Description": "demo",
        "File": "config/example.env",
        "StartLine": 1,
        "Redacted": "pk_****_demo",
    }
]


@pytest.fixture(autouse=True)
def override_db_session_for_scanner_safety(db_session):
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


def _analyst_token(client, demo_users, db_session) -> str:
    db_session.commit()
    return login(
        client,
        email="analyst@privacytrace.local",
        password="AnalystPass123!",
    )


UNSAFE_PAYLOADS = [
    pytest.param(
        {"Secret": "sk_live_REAL_SECRET_VALUE_12345"},
        ["sk_live_REAL_SECRET_VALUE_12345"],
        id="raw-secret-field",
    ),
    pytest.param(
        [{"Redacted": "ok", "Secret": "password=hunter2"}],
        ["hunter2", "password=hunter2"],
        id="password-in-finding",
    ),
    pytest.param(
        {
            "scanner": "generic_secret_scanner",
            "findings": [
                {
                    "masked_secret": "98******67",
                    "file": "a.log",
                    "line": 1,
                    "note": "phone 9812345678",
                }
            ],
        },
        ["9812345678"],
        id="raw-phone-in-generic",
    ),
    pytest.param(
        {
            "scanner": "generic_secret_scanner",
            "findings": [
                {
                    "masked_secret": "Bearer abcdef.ghijklm.opqrstuvwx",
                    "file": "a.log",
                    "line": 1,
                }
            ],
        },
        ["Bearer abcdef", "ghijklm"],
        id="bearer-token",
    ),
    pytest.param(
        {
            "scanner": "generic_secret_scanner",
            "findings": [
                {
                    "masked_secret": "sk-abcdefghijklmnopqrstuvwxyz123456",
                    "file": "config.env",
                    "line": 1,
                }
            ],
        },
        ["sk-abcdefghijklmnopqrstuvwxyz123456"],
        id="hyphen-api-key",
    ),
    pytest.param(
        {
            "scanner": "generic_secret_scanner",
            "findings": [
                {
                    "masked_secret": "accessToken=opaque-access-token-123456",
                    "file": "config.json",
                    "line": 2,
                }
            ],
        },
        ["opaque-access-token-123456"],
        id="access-token-field",
    ),
]


@pytest.mark.parametrize("payload,forbidden_fragments", UNSAFE_PAYLOADS)
def test_unsafe_scanner_import_rejected_without_echo(
    client_no_auth_override,
    demo_users,
    db_session,
    payload,
    forbidden_fragments,
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    fmt = (
        "gitleaks_json"
        if isinstance(payload, list)
        else "generic_secret_scanner_json"
    )
    response = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={"source_format": fmt, "payload": payload},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] in ("rejected", "partial")
    serialized = json.dumps(body)
    for fragment in forbidden_fragments:
        assert fragment not in serialized
    if body["status"] == "rejected":
        assert body["imported_count"] == 0


def test_preview_rejects_unsafe_top_level_payload(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/scanner-bridge/preview",
        headers=auth_headers(token),
        json={
            "source_format": "gitleaks_json",
            "payload": [{"Secret": "api_key=sk_test_AAAAAAAAAAAAAAAAAAAAAAAA"}],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["import_allowed"] is False
    assert "sk_test_AAAAAAAAAAAAAAAAAAAAAAAA" not in json.dumps(body)


def test_safe_import_succeeds(
    client_no_auth_override, demo_users, db_session
):
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={"source_format": "gitleaks_json", "payload": SAFE_GITLEAKS},
    )
    assert response.status_code == 200
    assert response.json()["imported_count"] >= 1


def test_finding_explanation_with_certainty_wording_is_imported_not_rejected(
    client_no_auth_override, demo_users, db_session
):
    """Phase P: a scanner finding's `explanation` text is INPUT evidence — it
    may quote the external tool's own wording ("proven cause of the
    breach"). It must not be rejected for that wording alone, only for raw
    secrets that cannot be safely masked."""
    token = _analyst_token(client_no_auth_override, demo_users, db_session)
    response = client_no_auth_override.post(
        "/scanner-bridge/import",
        headers=auth_headers(token),
        json={
            "source_format": "generic_secret_scanner_json",
            "payload": {
                "scanner": "generic_secret_scanner",
                "findings": [
                    {
                        "masked_secret": "pk_****",
                        "explanation": "This was the proven cause of the breach",
                        "file": "a.log",
                        "line": 1,
                    }
                ],
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] in ("accepted", "partial")
    assert body["imported_count"] >= 1
