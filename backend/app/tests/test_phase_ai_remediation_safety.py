from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.models import AIRemediationSuggestion, AuditLog
from app.services import ai_provider_client
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


def test_unsafe_input_is_blocked_before_provider_call(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, unsafe_nested=True)
    token = role_token(client_no_auth_override, db_session, "security_analyst")

    def fail_if_called(_payload):
        raise AssertionError("provider must not receive unsafe input")

    monkeypatch.setattr(ai_provider_client, "generate_remediation_suggestion", fail_if_called)
    response = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(token),
    )
    assert response.status_code == 422, response.text
    assert "9841234567" not in response.text

    row = db_session.scalar(select(AIRemediationSuggestion))
    assert row is not None
    assert row.status == "blocked_input_unsafe"
    assert row.input_safety_status == "blocked_input_unsafe"
    assert row.output_safety_status == "not_generated"
    assert row.masked_input_summary_hash.startswith("sha256:")

    actions = {log.action for log in db_session.scalars(select(AuditLog)).all()}
    assert "ai_remediation_input_blocked" in actions


def test_unsafe_ai_output_is_blocked_and_not_displayed(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-002")
    token = role_token(client_no_auth_override, db_session, "security_analyst")

    def unsafe_output(_payload):
        return ai_provider_client.AIProviderResult(
            provider="mock",
            model="unsafe-mock",
            content={
                "suggestion_summary": "The issue is guaranteed fixed and can be closed.",
                "remediation_actions": ["No human review needed."],
            },
        )

    monkeypatch.setattr(ai_provider_client, "generate_remediation_suggestion", unsafe_output)
    response = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(token),
    )
    assert response.status_code == 422, response.text
    assert "guaranteed fixed" not in response.text.lower()

    row = db_session.scalar(select(AIRemediationSuggestion))
    assert row is not None
    assert row.status == "blocked_output_unsafe"
    assert row.suggestion_summary is None
    actions = {log.action for log in db_session.scalars(select(AuditLog)).all()}
    assert "ai_remediation_output_blocked" in actions


def test_provider_failure_creates_failed_safe_record(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-003")
    token = role_token(client_no_auth_override, db_session, "security_analyst")

    def provider_failure(_payload):
        raise ai_provider_client.AIProviderError("AI provider unavailable")

    monkeypatch.setattr(ai_provider_client, "generate_remediation_suggestion", provider_failure)
    response = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(token),
    )
    assert response.status_code == 503, response.text

    row = db_session.scalar(select(AIRemediationSuggestion))
    assert row is not None
    assert row.status == "failed"
    assert row.input_safety_status == "safe_masked_input"
    assert row.output_safety_status == "not_generated"
    assert "9841234567" not in json.dumps(response.json())


def test_reviewer_notes_with_raw_or_overclaim_content_are_rejected(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-004")
    token = role_token(client_no_auth_override, db_session, "security_analyst")
    generated = client_no_auth_override.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(token),
    )
    suggestion_id = generated.json()["suggestion"]["suggestion_id"]

    raw_note = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/accept",
        headers=auth_headers(token),
        json={"reviewer_notes": "phone 9841234567 is the proven cause", "create_remediation_action": True},
    )
    assert raw_note.status_code == 422, raw_note.text
    assert "9841234567" not in raw_note.text

    row = db_session.scalar(
        select(AIRemediationSuggestion).where(AIRemediationSuggestion.suggestion_id == suggestion_id)
    )
    assert row is not None
    assert row.reviewer_decision is None
    assert row.accepted_as_remediation_action_id is None
