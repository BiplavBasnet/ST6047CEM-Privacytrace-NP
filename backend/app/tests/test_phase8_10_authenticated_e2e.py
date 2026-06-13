"""Authenticated Phase 8-10 workflow against dedicated PostgreSQL only."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.config import resolve_sample_data_dir
from app.db.seed_auth_users import seed_auth_users
from app.dependencies.auth_dependencies import get_current_user
from app.main import app


INCIDENT_ID = "INC-SEED-001"
pytestmark = [
    pytest.mark.integration,
    pytest.mark.postgres,
    pytest.mark.critical_db,
    pytest.mark.e2e,
]


def _assert_ok(response, expected: int = 200) -> dict:
    assert response.status_code == expected, response.text
    return response.json()


def _login(client: TestClient, email: str, password: str) -> tuple[dict[str, str], dict]:
    body = _assert_ok(client.post("/auth/login", json={"email": email, "password": password}))
    return {"Authorization": f"Bearer {body['access_token']}"}, body["user"]


def test_authenticated_phase8_to_phase10_workflow_and_auditor_boundary(
    client: TestClient,
    seeded_db,
):
    app.dependency_overrides.pop(get_current_user, None)
    seed_auth_users()

    analyst_headers, analyst = _login(
        client,
        "analyst@privacytrace.local",
        "AnalystPass123!",
    )

    _assert_ok(
        client.post(
            "/evidence/load-sample",
            headers=analyst_headers,
            json={"scenario": "scenario_1"},
        )
    )
    _assert_ok(client.post("/evidence/parse-all", headers=analyst_headers))
    _assert_ok(client.post("/evidence/detect-all", headers=analyst_headers))
    analysis = _assert_ok(
        client.post(
            "/incidents/analyse",
            headers=analyst_headers,
            json={"incident_id": INCIDENT_ID},
        )
    )
    assert any(item["incident_id"] == INCIDENT_ID for item in analysis["results"])

    review = _assert_ok(
        client.post(
            f"/incidents/{INCIDENT_ID}/review",
            headers=analyst_headers,
            json={
                "decision": "approved",
                "reason": "Masked evidence supports the reviewed remediation action.",
            },
        )
    )
    assert review["review"]["reviewer_id"] == analyst["id"]
    assert review["incident_status"] == "confirmed_incident"

    diagnosis = _assert_ok(
        client.post(
            f"/ai-remediation/incidents/{INCIDENT_ID}/diagnose",
            headers=analyst_headers,
        )
    )
    diagnosis_id = diagnosis.get("diagnosis_id") or diagnosis["diagnosis"]["diagnosis_id"]
    accepted = _assert_ok(
        client.post(
            f"/ai-remediation/diagnoses/{diagnosis_id}/review",
            headers=analyst_headers,
            json={"decision": "accept", "notes": "Accept governed diagnosis for e2e gate check."},
        )
    )
    assert accepted["status"] in {"accepted", "accepted_with_edits"}

    retest_content = (
        resolve_sample_data_dir() / "retest_evidence" / "wallet_transfer_retest.log"
    ).read_bytes() + b"\n# authenticated-phase8-10-e2e\n"
    upload = _assert_ok(
        client.post(
            "/evidence/upload",
            headers=analyst_headers,
            files={"file": ("authenticated_e2e_retest.log", retest_content, "text/plain")},
            data={
                "evidence_type": "fixed_log",
                "linked_incident_id": INCIDENT_ID,
                "source_system": "wallet-service",
            },
        ),
        expected=201,
    )
    retest_evidence_id = upload["evidence"]["evidence_id"]

    verification = client.post(
        f"/incidents/{INCIDENT_ID}/verify-fix",
        headers=analyst_headers,
        json={"retest_evidence_ids": [retest_evidence_id]},
    )
    assert verification.status_code == 422, verification.text
    detail = verification.text.lower()
    assert any(
        token in detail
        for token in ("controlled retest", "implementation", "diagnosis", "awaiting retest", "action")
    )

    report = _assert_ok(
        client.post(
            f"/reports/incidents/{INCIDENT_ID}/generate",
            headers=analyst_headers,
            json={"report_type": "json"},
        )
    )
    assert report["content"]["incident_id"] == INCIDENT_ID
    assert retest_evidence_id in report["content"]["linked_evidence_ids"]

    metrics = _assert_ok(
        client.post(
            "/metrics/evaluation/run",
            headers=analyst_headers,
            json={"scenario_name": "scenario_1"},
        )
    )
    assert metrics["metrics_computed"] > 0

    audit = _assert_ok(
        client.get(
            "/audit-logs",
            headers=analyst_headers,
            params={"incident_id": INCIDENT_ID},
        )
    )
    assert any(log["action"] == "review_submitted" for log in audit["logs"])

    auditor_headers, _ = _login(
        client,
        "auditor@privacytrace.local",
        "AuditorPass123!",
    )
    listed_reviews = _assert_ok(
        client.get(f"/incidents/{INCIDENT_ID}/reviews", headers=auditor_headers)
    )
    assert listed_reviews["total"] >= 1
    denied = client.post(
        f"/incidents/{INCIDENT_ID}/review",
        headers=auditor_headers,
        json={
            "decision": "inconclusive",
            "reason": "Auditors can inspect reviews but cannot submit decisions.",
        },
    )
    assert denied.status_code == 403
