"""Workflow integrity, remediation, evidence-strength, and readiness tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.dependencies import get_db_session
from app.services import root_cause_analysis_service
from app.main import app
from app.models import (
    AuditLog,
    EvidenceFile,
    FixVerification,
    Incident,
    Report,
    ReviewDecision,
    RootCauseScore,
    User,
)
from app.models.enums import (
    EvidenceType,
    IncidentStatus,
    ParsingStatus,
    Severity,
    UserRole,
    VerificationStatus,
)

INCIDENT_ID = "INC-WORKFLOW-001"


@pytest.fixture
def workflow_env(db_session):
    user = User(
        name="Workflow Admin",
        email="workflow-admin@example.test",
        role=UserRole.ADMIN,
        is_active=True,
    )
    incident = Incident(
        incident_id=INCIDENT_ID,
        title="Possible privacy exposure in payment-api /payments",
        affected_service="payment-api",
        affected_endpoint="/payments",
        status=IncidentStatus.UNDER_REVIEW,
        severity=Severity.HIGH,
        first_seen=datetime(2026, 7, 15, 5, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 7, 15, 5, 5, tzinfo=timezone.utc),
        summary="Masked sensitive-data exposure requires human review.",
    )
    evidence = EvidenceFile(
        evidence_id="EVD-WORKFLOW-LOG",
        file_name="masked-api-log.json",
        evidence_type=EvidenceType.API_LOG,
        source_system="payment-api",
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=INCIDENT_ID,
    )
    root = RootCauseScore(
        root_cause_id="RC-WORKFLOW-001",
        incident_id=INCIDENT_ID,
        cause_name="logging configuration",
        likely_root_cause="Request logging may have omitted redaction",
        confidence=0.91,
        confidence_band="high",
        rank=1,
        supporting_evidence_ids=["EVD-WORKFLOW-LOG"],
        missing_evidence=["Deployment or configuration evidence is missing."],
        score_breakdown=[],
        matched_signals=[{"signal_name": "masked_log", "matched": True}],
        negative_signals=[],
        correlation_reasons=["Masked log evidence matches the affected endpoint."],
        contradicting_evidence=[],
        evidence_roles=[{"evidence_id": "EVD-WORKFLOW-LOG", "role": "symptom"}],
        suggested_actions=[],
        human_review_required=True,
        explanation="Available evidence supports a likely logging contribution.",
    )
    db_session.add_all([user, incident, evidence, root])
    db_session.flush()
    analysis = root_cause_analysis_service.ensure_seed_analysis_for_incident(db_session, INCIDENT_ID)
    root.analysis_id = analysis.analysis_id
    root.analysis_version = analysis.analysis_version
    root.evidence_snapshot_hash = analysis.evidence_snapshot_hash
    db_session.add(root)
    db_session.flush()

    def override_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_db
    yield {"db": db_session, "user": user, "incident": incident, "root": root}
    app.dependency_overrides.pop(get_db_session, None)


def submit_review(client, decision: str):
    return client.post(
        f"/incidents/{INCIDENT_ID}/review",
        json={
            "decision": decision,
            "reason": "Masked evidence and stated limitations were reviewed.",
            "evidence_checklist": ["Supporting evidence reviewed"],
            "evidence_relied_on": ["EVD-WORKFLOW-LOG"],
            "evidence_limitations": "Technical evidence remains limited.",
            "missing_evidence_acknowledged": True,
        },
    )


def create_remediation(client, status="awaiting_retest"):
    return client.post(
        f"/incidents/{INCIDENT_ID}/remediation-actions",
        json={
            "action_type": "redaction_rule_update",
            "action_description": "Update the payment logging redaction rule.",
            "affected_component": "payment-api logging middleware",
            "assigned_owner": "payments platform team",
            "status": status,
            "priority": "high",
            "retest_required": True,
        },
    )


def test_workflow_state_returns_all_six_backend_stages(client, workflow_env):
    response = client.get(f"/incidents/{INCIDENT_ID}/workflow-state")
    assert response.status_code == 200
    body = response.json()
    assert [item["code"] for item in body["stages"]] == [
        "overview",
        "root_cause",
        "human_review",
        "remediation",
        "fix_verification",
        "final_report",
    ]
    assert body["next_action"]["code"] == "complete_human_review"


def test_review_draft_persists_but_does_not_unlock_remediation(client, workflow_env):
    saved = client.put(
        f"/incidents/{INCIDENT_ID}/review-draft",
        json={
            "selected_decision": "approved",
            "reason": "Draft only; more review is needed.",
            "evidence_checklist": ["Supporting evidence reviewed"],
            "evidence_relied_on": ["EVD-WORKFLOW-LOG"],
            "missing_evidence_acknowledged": True,
        },
    )
    assert saved.status_code == 200
    restored = client.get(f"/incidents/{INCIDENT_ID}/review-draft")
    assert restored.json()["reason"] == "Draft only; more review is needed."
    state = client.get(f"/incidents/{INCIDENT_ID}/workflow-state").json()
    remediation = next(item for item in state["stages"] if item["code"] == "remediation")
    assert remediation["available"] is False
    assert state["next_action"]["code"] == "complete_human_review"


@pytest.mark.parametrize(
    "decision",
    ["request_more_evidence", "rejected_false_positive", "escalated"],
)
def test_non_approved_reviews_do_not_unlock_remediation(client, workflow_env, decision):
    response = submit_review(client, decision)
    assert response.status_code == 200
    state = client.get(f"/incidents/{INCIDENT_ID}/workflow-state").json()
    remediation = next(item for item in state["stages"] if item["code"] == "remediation")
    assert remediation["available"] is False


def test_approved_review_unlocks_remediation_and_removes_draft(client, workflow_env):
    client.put(
        f"/incidents/{INCIDENT_ID}/review-draft",
        json={"selected_decision": "approved", "reason": "Temporary draft."},
    )
    assert submit_review(client, "approved").status_code == 200
    state = client.get(f"/incidents/{INCIDENT_ID}/workflow-state").json()
    remediation = next(item for item in state["stages"] if item["code"] == "remediation")
    assert remediation["available"] is True
    assert client.get(f"/incidents/{INCIDENT_ID}/review-draft").json() is None


def test_remediation_action_persists_and_creates_audit_log(client, workflow_env):
    assert submit_review(client, "approved").status_code == 200
    response = create_remediation(client)
    assert response.status_code == 200, response.text
    action_id = response.json()["remediation_action_id"]
    listed = client.get(f"/incidents/{INCIDENT_ID}/remediation-actions").json()
    assert listed["total"] == 1
    assert listed["remediation_actions"][0]["remediation_action_id"] == action_id
    db = workflow_env["db"]
    audit = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "remediation_action_created",
            AuditLog.target_id == action_id,
        )
    )
    assert audit is not None


def test_fix_verification_requires_approved_review(client, workflow_env):
    response = client.post(f"/incidents/{INCIDENT_ID}/verify-fix", json={})
    assert response.status_code == 422
    assert "approved" in response.json()["detail"].lower() or "review" in response.json()["detail"].lower()


def test_fix_verification_requires_remediation(client, workflow_env):
    submit_review(client, "approved")
    response = client.post(f"/incidents/{INCIDENT_ID}/verify-fix", json={})
    assert response.status_code == 422
    assert "remediation" in response.json()["detail"].lower()


def test_fix_verification_requires_retest_evidence(client, workflow_env):
    submit_review(client, "approved")
    create_remediation(client)
    response = client.post(f"/incidents/{INCIDENT_ID}/verify-fix", json={})
    assert response.status_code == 422
    assert "retest" in response.json()["detail"].lower() or "diagnosis" in response.json()["detail"].lower()


def test_report_existence_does_not_proxy_review_or_verification(client, workflow_env):
    db = workflow_env["db"]
    db.add(Report(incident_id=INCIDENT_ID, report_type="json", content_json={"safe": True}))
    db.flush()
    readiness = client.get(f"/incidents/{INCIDENT_ID}/report-readiness").json()
    assert readiness["report_ready"] is False
    assert readiness["checks"]["human_review_recorded"] is False
    assert readiness["checks"]["fix_verification_available"] is False


def test_report_readiness_uses_real_completed_workflow(client, workflow_env):
    submit_review(client, "approved")
    create_remediation(client)
    db = workflow_env["db"]
    db.add(
        EvidenceFile(
            evidence_id="EVD-WORKFLOW-RETEST",
            file_name="masked-fixed-log.json",
            evidence_type=EvidenceType.FIXED_LOG,
            source_system="payment-api",
            parsing_status=ParsingStatus.PARSED,
            linked_incident_id=INCIDENT_ID,
        )
    )
    db.add(
        FixVerification(
            incident_id=INCIDENT_ID,
            verification_status=VerificationStatus.PASSED,
            checks_run=["retest_evidence_present"],
            passed_checks=["retest_evidence_present"],
            failed_checks=[],
            evidence_used=["EVD-WORKFLOW-RETEST"],
        )
    )
    db.flush()
    readiness = client.get(f"/incidents/{INCIDENT_ID}/report-readiness").json()
    assert readiness["report_ready"] is False
    assert readiness["blocking_items"]


def test_log_only_evidence_is_backend_capped(client, workflow_env):
    result = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    assert result["technical_evidence_count"] == 0
    assert result["confidence_cap_score"] <= 0.65
    assert result["confidence_score"] <= result["confidence_cap_score"]
    assert result["evidence_strength_level"] in {"weak", "medium"}


def test_structured_cicd_evidence_strengthens_technical_confidence(client, workflow_env):
    before = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    imported = client.post(
        "/cicd-evidence/import",
        json={
            "source_name": "github-actions",
            "evidence_type": "configuration_change",
            "environment": "test",
            "service_name": "payment-api",
            "deployment_version": "v2.1.0",
            "changed_file_paths_safe": ["src/logging/redaction.py"],
            "change_categories": ["logging", "redaction", "configuration"],
            "scan_summary_safe": "A logging redaction configuration changed before the alert.",
            "event_time": "2026-07-15T04:30:00Z",
            "linked_incident_id": INCIDENT_ID,
        },
    )
    assert imported.status_code == 200, imported.text
    after = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    assert after["technical_evidence_count"] > before["technical_evidence_count"]
    assert after["confidence_cap_score"] > before["confidence_cap_score"]


def test_contradicting_evidence_reduces_confidence(client, workflow_env):
    before = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    workflow_env["root"].contradicting_evidence = [
        {"evidence_id": "EVD-CONTRA-1", "reason": "A later control record conflicts with the timeline."}
    ]
    workflow_env["db"].flush()
    after = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    assert after["confidence_cap_score"] < before["confidence_cap_score"]
    assert after["confidence_score"] <= before["confidence_score"]
    assert after["contradicting_evidence"]


def test_missing_metadata_reduces_confidence(client, workflow_env):
    incident = workflow_env["incident"]
    with_context = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    incident.affected_service = None
    incident.affected_endpoint = None
    workflow_env["db"].flush()
    without_context = client.get(
        f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength"
    ).json()
    assert without_context["confidence_cap_score"] < with_context["confidence_cap_score"]
    assert any("service" in item.lower() for item in without_context["missing_evidence"])


def test_workflow_responses_mask_raw_values_and_avoid_forbidden_wording(client, workflow_env):
    draft = client.put(
        f"/incidents/{INCIDENT_ID}/review-draft",
        json={
            "selected_decision": "request_more_evidence",
            "reason": "Review phone 9841234567 in masked evidence.",
        },
    )
    assert draft.status_code == 200
    combined = " ".join(
        [
            draft.text,
            client.get(f"/incidents/{INCIDENT_ID}/workflow-state").text,
            client.get(f"/incidents/{INCIDENT_ID}/root-cause-evidence-strength").text,
            client.get(f"/incidents/{INCIDENT_ID}/report-readiness").text,
        ]
    ).lower()
    assert "9841234567" not in combined
    for phrase in [
        "proven root cause",
        "confirmed blame",
        "guaranteed fixed",
        "attacker accessed data",
        "ai solved the issue",
    ]:
        assert phrase not in combined


def test_browser_preflight_allows_review_draft_put(client):
    response = client.options(
        f"/incidents/{INCIDENT_ID}/review-draft",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert response.status_code == 200
    allowed = response.headers["access-control-allow-methods"]
    assert "PUT" in {method.strip() for method in allowed.split(",")}


def test_failed_verification_outcome_does_not_complete_report_stage(client, workflow_env, monkeypatch):
    assert submit_review(client, "approved").status_code == 200
    from app.services import workflow_provenance_service

    def _failed_chain(_db, _incident_id):
        return {
            "workflow_chain_status": "current",
            "blocked_reasons": [],
            "remediation_action_status": "awaiting_retest",
            "implementation_status": "completed",
            "test_execution_status": "passed",
            "controlled_retest_status": "completed",
            "verification_outcome": "failed",
            "verification_outcome_id": "VO-FAILED",
        }

    monkeypatch.setattr(
        workflow_provenance_service, "get_workflow_provenance_facts", _failed_chain
    )
    state = client.get(f"/incidents/{INCIDENT_ID}/workflow-state").json()
    verify = next(stage for stage in state["stages"] if stage["code"] == "fix_verification")
    report = next(stage for stage in state["stages"] if stage["code"] == "final_report")
    assert verify["completed"] is False
    assert report["available"] is False
    readiness = client.get(f"/incidents/{INCIDENT_ID}/report-readiness").json()
    assert readiness["report_ready"] is False
    assert readiness["checks"]["fix_verification_available"] is False

