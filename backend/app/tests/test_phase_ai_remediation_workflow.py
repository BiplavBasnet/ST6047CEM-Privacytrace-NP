from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import AIRemediationSuggestion, FixVerification, Incident
from app.models.enums import IncidentStatus
from app.services import review_service
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


def _generate(client, db_session, token: str, incident_id: str) -> str:
    response = client.post(
        f"/ai-remediation/incidents/{incident_id}/suggest",
        headers=auth_headers(token),
    )
    assert response.status_code == 200, response.text
    return response.json()["suggestion"]["suggestion_id"]


def test_accept_creates_advisory_reference_without_closing_or_verifying_incident(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-WF1")
    review_service.submit_review(
        db_session,
        incident_id,
        decision="approved",
        reason="Masked evidence supports remediation planning.",
        evidence_checklist=["detections"],
        missing_evidence_acknowledged=True,
    )
    token = role_token(client_no_auth_override, db_session, "security_analyst")
    suggestion_id = _generate(client_no_auth_override, db_session, token, incident_id)

    accepted = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/accept",
        headers=auth_headers(token),
        json={
            "reviewer_notes": "Accepted for remediation planning using masked evidence only.",
            "create_remediation_action": True,
        },
    )
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body["status"] == "accepted_by_reviewer"
    assert body["reviewer_decision"] == "accepted"

    incident = db_session.scalar(select(Incident).where(Incident.incident_id == incident_id))
    assert incident.status != IncidentStatus.CLOSED
    assert db_session.scalar(select(FixVerification)) is None

    row = db_session.scalar(
        select(AIRemediationSuggestion).where(AIRemediationSuggestion.suggestion_id == suggestion_id)
    )
    assert row.status == "accepted_by_reviewer"
    assert row.reviewer_decision == "accepted"


def test_reviewer_can_edit_then_accept_suggestion(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-WF2")
    token = role_token(client_no_auth_override, db_session, "devsecops_engineer")
    suggestion_id = _generate(client_no_auth_override, db_session, token, incident_id)

    edited = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/edit",
        headers=auth_headers(token),
        json={
            "edited_remediation_actions": [
                "Update wallet-service redaction middleware before log emission.",
                "Add retest log evidence after deployment.",
            ],
            "reviewer_notes": "Reviewer narrowed the action list.",
        },
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["status"] == "edited_by_reviewer"

    accepted = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/accept",
        headers=auth_headers(token),
        json={"reviewer_notes": "Edited action accepted for planning.", "create_remediation_action": False},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "accepted_by_reviewer"

    row = db_session.scalar(
        select(AIRemediationSuggestion).where(AIRemediationSuggestion.suggestion_id == suggestion_id)
    )
    assert row.remediation_actions == [
        "Update wallet-service redaction middleware before log emission.",
        "Add retest log evidence after deployment.",
    ]


def test_reject_requires_reason_and_prevents_later_accept(
    client_no_auth_override,
    demo_users,
    db_session,
    monkeypatch,
):
    enable_mock_ai(monkeypatch)
    incident_id = seed_ai_incident(db_session, incident_id="INC-AI-WF3")
    token = role_token(client_no_auth_override, db_session, "security_analyst")
    suggestion_id = _generate(client_no_auth_override, db_session, token, incident_id)

    missing_reason = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/reject",
        headers=auth_headers(token),
        json={},
    )
    assert missing_reason.status_code == 422

    rejected = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/reject",
        headers=auth_headers(token),
        json={"reason": "Reviewer rejected this suggestion because it was not specific enough."},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "rejected_by_reviewer"

    late_accept = client_no_auth_override.post(
        f"/ai-remediation/suggestions/{suggestion_id}/accept",
        headers=auth_headers(token),
        json={"reviewer_notes": "late accept", "create_remediation_action": False},
    )
    assert late_accept.status_code == 422

    incident = db_session.scalar(select(Incident).where(Incident.incident_id == incident_id))
    assert incident.status == IncidentStatus.NEW
