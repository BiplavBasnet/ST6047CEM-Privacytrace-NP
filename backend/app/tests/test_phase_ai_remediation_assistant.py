from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.models import AIRemediationSuggestion
from app.tests.ai_remediation_test_helpers import (
    clear_ai_settings,
    enable_mock_ai,
    role_token,
    seed_ai_incident,
)
from app.tests.auth_test_utils import auth_headers, seed_demo_users_in_db

pytestmark = pytest.mark.usefixtures("migrated_db")


@pytest.fixture(autouse=True)
def ai_settings_cleanup(monkeypatch):
    clear_ai_settings(monkeypatch)
    yield
    clear_ai_settings(monkeypatch)


@pytest.fixture(autouse=True)
def override_db_session_for_ai_remediation(db_session):
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


def test_ai_remediation_route_requires_auth(client_no_auth_override):
    response = client_no_auth_override.get("/ai-remediation/status")
    assert response.status_code == 401


def test_status_disabled_by_default(client_no_auth_override, demo_users, db_session):
    token = role_token(client_no_auth_override, db_session, "auditor")
    response = client_no_auth_override.get(
        "/ai-remediation/status",
        headers=auth_headers(token),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enabled"] is False
    assert body["provider_configured"] is False
    assert body["safety_gateway_enabled"] is True
    assert "api_key" not in json.dumps(body).lower()


def test_generate_list_detail_and_final_report_include_safe_suggestion(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session)
    token = role_token(client_no_auth_override, db_session, "security_analyst")

    generated = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(token),
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    suggestion = body["suggestion"]
    assert suggestion["status"] == "generated"
    assert suggestion["human_review_required"] is True
    assert suggestion["input_safety_status"] == "safe_masked_input"
    assert suggestion["output_safety_status"] == "safe_output"
    assert suggestion["remediation_actions"]
    blob = json.dumps(body)
    assert "9841234567" not in blob
    assert "raw_value" not in blob.lower()
    assert "guaranteed fixed" not in blob.lower()

    row = db_session.scalar(
        select(AIRemediationSuggestion).where(
            AIRemediationSuggestion.suggestion_id == suggestion["suggestion_id"]
        )
    )
    assert row is not None
    assert row.masked_input_summary_hash.startswith("sha256:")

    listed = client_no_auth_override.get(
        f"/ai-remediation/incidents/{incident_id}/suggestions",
        headers=auth_headers(token),
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1

    detail = client_no_auth_override.get(
        f"/ai-remediation/suggestions/{suggestion['suggestion_id']}",
        headers=auth_headers(token),
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["suggestion_id"] == suggestion["suggestion_id"]

    final_report = client_no_auth_override.get(
        f"/reports/incidents/{incident_id}/final-report.json",
        headers=auth_headers(token),
    )
    assert final_report.status_code == 200, final_report.text
    report_body = final_report.json()
    assert report_body["ai_remediation_suggestions"][0]["suggestion_id"] == suggestion["suggestion_id"]
    report_blob = json.dumps(report_body).lower()
    assert "ai remediation suggestions are advisory" in report_blob
    assert "9841234567" not in report_blob
    assert "incident closed automatically" not in report_blob
