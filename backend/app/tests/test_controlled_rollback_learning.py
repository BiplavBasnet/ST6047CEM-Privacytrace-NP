"""Controlled rollback ledger + verified learning ranking (targeted)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.models.rollback_execution import RollbackExecution
from app.models.verified_remediation_learning import VerifiedRemediationCase
from app.services import (
    ai_remediation_diagnosis_service,
    controlled_patch_service,
    controlled_rollback_service,
    sandbox_test_execution_service,
    verified_outcome_learning_service,
)
from app.tests.ai_remediation_test_helpers import seed_ai_incident
from app.tests.test_gold_standard_verified_remediation import (
    GOLD_FILE,
    _analyst,
    _approve,
    _attach_sast,
)

pytestmark = pytest.mark.usefixtures("migrated_db")


def _accept_and_apply(db, monkeypatch, incident_id: str):
    monkeypatch.setenv("REMEDIATION_REPO_ALLOWLIST", "fixtures")
    get_settings.cache_clear()
    _attach_sast(db, incident_id)
    _approve(db, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db, incident_id, **_analyst(db)
    )
    if not row.exact_source_location_known:
        pytest.fail("expected exact source location from SAST evidence")
    accepted = ai_remediation_diagnosis_service.review_diagnosis(
        db,
        row.diagnosis_id,
        decision="accept",
        notes="Accept for rollback test.",
        edited_primary=None,
        **_analyst(db),
    )
    from app.models.remediation_action import RemediationAction

    action = db.scalar(
        select(RemediationAction).where(RemediationAction.diagnosis_id == accepted.diagnosis_id)
    )
    assert action is not None
    if not accepted.proposed_change:
        accepted.proposed_change = {
            "change_type": "code_patch",
            "file_path": GOLD_FILE,
            "proposed_diff": "# gold",
            "change_summary": "redact auth",
            "base_content_hash": "fixture",
            "why_each_change_is_needed": ["redact"],
            "expected_security_effect": "no raw token",
            "tests_required": ["regression"],
        }
        accepted.exact_source_location_known = True
        accepted.affected_file = GOLD_FILE
        db.add(accepted)
        db.commit()
    patch = controlled_patch_service.generate_real_patch_proposal(
        db, accepted, remediation_action_id=action.remediation_action_id, **_analyst(db)
    )
    assert patch.base_source_hash  # PreChangeSnapshot exists before apply
    controlled_patch_service.approve_patch_for_sandbox(db, patch.patch_proposal_id, **_analyst(db))
    applied = controlled_patch_service.apply_patch_to_sandbox(db, patch.patch_proposal_id, **_analyst(db))
    assert applied.pre_test_workspace_hash == applied.post_apply_workspace_hash
    return accepted, action, applied


def test_prechange_snapshot_before_apply_and_test_fail_rolls_back(db_session, monkeypatch):
    incident_id = seed_ai_incident(db_session, incident_id="INC-RB-TESTFAIL")
    _, action, patch = _accept_and_apply(db_session, monkeypatch, incident_id)
    from app.models.workflow_verification import RemediationImplementationRecord

    impl = db_session.scalar(
        select(RemediationImplementationRecord).where(
            RemediationImplementationRecord.patch_proposal_id == patch.patch_proposal_id
        )
    )
    assert impl is not None

    def _boom(*_a, **_k):
        class R:
            returncode = 1
            stdout = "FAILED"
            stderr = ""

        return R()

    monkeypatch.setattr(sandbox_test_execution_service.subprocess, "run", _boom)
    result = sandbox_test_execution_service.run_profile(
        "synthetic_request_logger_regression",
        sandbox_workspace=patch.temporary_workspace,
        db=db_session,
        incident_id=incident_id,
        remediation_action_id=action.remediation_action_id,
        patch_proposal_id=patch.patch_proposal_id,
        patch=patch,
        implementation_id=impl.implementation_id,
        actor_id=_analyst(db_session)["actor_id"],
        executed_by="analyst",
    )
    assert result["status"] == "failed"
    assert result.get("rollback_execution_id")
    rb = db_session.scalar(
        select(RollbackExecution).where(
            RollbackExecution.rollback_execution_id == result["rollback_execution_id"]
        )
    )
    assert rb is not None
    assert rb.status == "succeeded"
    assert rb.rollback_verified is True
    assert rb.verification_result == "passed"
    assert rb.restored_hashes.get("request_logger.py") == patch.base_source_hash
    db_session.refresh(patch)
    assert patch.rollback_status == "rolled_back"
    again = controlled_rollback_service.execute_controlled_rollback(
        db_session,
        patch_proposal_id=patch.patch_proposal_id,
        trigger=controlled_rollback_service.TRIGGER_TEST_FAILED,
        trigger_reference=result["execution_id"],
        performed_mode=controlled_rollback_service.MODE_AUTOMATIC,
    )
    assert again.rollback_execution_id == rb.rollback_execution_id


def test_apply_writes_lf_and_hashes_written_bytes(db_session, monkeypatch):
    incident_id = seed_ai_incident(db_session, incident_id="INC-RB-CRLFHASH")
    _, _, patch = _accept_and_apply(db_session, monkeypatch, incident_id)
    target = Path(patch.temporary_workspace) / "fixtures" / "gold_standard_wallet" / "request_logger.py"
    raw = target.read_bytes()
    assert b"\r\n" not in raw
    assert patch.post_apply_workspace_hash == f"sha256:{hashlib.sha256(raw).hexdigest()}"
    orig = target.parent / "request_logger.py.orig"
    orig_raw = orig.read_bytes()
    assert b"\r\n" not in orig_raw
    assert patch.base_source_hash == f"sha256:{hashlib.sha256(orig_raw).hexdigest()}"
    from app.services import controlled_rollback_service

    rb = controlled_rollback_service.execute_controlled_rollback(
        db_session,
        patch_proposal_id=patch.patch_proposal_id,
        trigger=controlled_rollback_service.TRIGGER_HUMAN,
        performed_mode=controlled_rollback_service.MODE_HUMAN,
        actor_id=_analyst(db_session)["actor_id"],
    )
    assert rb.status == "succeeded"
    assert rb.restored_hashes.get("request_logger.py") == patch.base_source_hash


def test_startup_recovery_restores_interrupted_apply(db_session, monkeypatch):
    incident_id = seed_ai_incident(db_session, incident_id="INC-RB-RECOVER")
    _, _, patch = _accept_and_apply(db_session, monkeypatch, incident_id)
    # Simulate crash mid-apply bookkeeping
    patch.last_known_state = "apply_interrupted"
    patch.recovery_required = True
    patch.status = "applying"
    db_session.add(patch)
    db_session.commit()
    results = controlled_rollback_service.recover_incomplete_patches(db_session)
    assert any(r["patch_proposal_id"] == patch.patch_proposal_id for r in results)
    db_session.refresh(patch)
    assert patch.rollback_status == "rolled_back"
    assert patch.recovery_required is False


def test_failed_learning_not_eligible_and_negative_ranking(db_session, monkeypatch):
    monkeypatch.setenv("REMEDIATION_REPO_ALLOWLIST", "fixtures")
    get_settings.cache_clear()
    fp = verified_outcome_learning_service.remediation_fingerprint(
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="authorization_header",
        exposure_location="application_logs",
        affected_component="request logging middleware",
        implementation_mode="controlled_patch",
    )
    incident_id = seed_ai_incident(db_session, incident_id="INC-LEARN-NEG")
    case = VerifiedRemediationCase(
        verified_case_id="VRC-FAILTEST01",
        incident_id=incident_id,
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="authorization_header",
        exposure_location="application_logs",
        affected_component="request logging middleware",
        remediation_fingerprint=fp,
        verification_result="failed",
        eligible_for_learning=False,
        eligibility_reason="Failed remediation is not a success exemplar.",
        policy_version="playbook-v1",
        semantics_version="v2",
        limitations=[],
        workflow_status="current",
    )
    db_session.add(case)
    db_session.commit()
    influence = verified_outcome_learning_service.ranking_influence_for_similar(
        db_session,
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="authorization_header",
        exposure_location="application_logs",
        affected_component="request logging middleware",
        implementation_mode="controlled_patch",
    )
    assert influence["negative_fingerprint_hits"] >= 1
    assert "VRC-FAILTEST01" not in influence["case_ids"]
    assert influence["human_review_required"] is True


def test_similar_verified_case_ranks_above_unrelated(db_session):
    a = seed_ai_incident(db_session, incident_id="INC-RANK-A")
    b = seed_ai_incident(db_session, incident_id="INC-RANK-B")
    match = VerifiedRemediationCase(
        verified_case_id="VRC-MATCH0001",
        incident_id=a,
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="pan",
        exposure_location="application_logs",
        affected_component="logger",
        verification_result="passed",
        eligible_for_learning=True,
        eligibility_reason="ok",
        policy_version="playbook-v1",
        semantics_version="v2",
        limitations=[],
        workflow_status="current",
        remediation_fingerprint="rfp:match",
    )
    other = VerifiedRemediationCase(
        verified_case_id="VRC-OTHER0001",
        incident_id=b,
        remediation_type="access_control_tightening",
        root_cause_category="overbroad_role",
        sensitive_type="email",
        exposure_location="api_response",
        affected_component="gateway",
        verification_result="passed",
        eligible_for_learning=True,
        eligibility_reason="ok",
        policy_version="playbook-v1",
        semantics_version="v2",
        limitations=[],
        workflow_status="current",
        remediation_fingerprint="rfp:other",
    )
    db_session.add_all([match, other])
    db_session.commit()
    ranked = verified_outcome_learning_service.ranking_influence_for_similar(
        db_session,
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="pan",
        exposure_location="application_logs",
        affected_component="logger",
    )
    assert ranked["ranked_cases"]
    assert ranked["ranked_cases"][0]["verified_case_id"] == "VRC-MATCH0001"
    assert ranked["ranked_cases"][0]["score"] > 0
    assert "matched" in " ".join(ranked["ranked_cases"][0]["why_selected"])


def test_fingerprint_blocks_after_budget(db_session, monkeypatch):
    monkeypatch.setenv("REMEDIATION_MAX_FAILED_ATTEMPTS", "2")
    get_settings.cache_clear()
    incident_id = seed_ai_incident(db_session, incident_id="INC-FP-BUDGET")
    fp = verified_outcome_learning_service.remediation_fingerprint(
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="pan",
        exposure_location="application_logs",
        affected_component="logger",
        implementation_mode="controlled_patch",
    )
    for i in range(2):
        db_session.add(
            VerifiedRemediationCase(
                verified_case_id=f"VRC-BUDGET{i:02d}",
                incident_id=incident_id,
                remediation_type="request_body_redaction",
                root_cause_category="unsafe_request_body_logging",
                sensitive_type="pan",
                exposure_location="application_logs",
                affected_component="logger",
                remediation_fingerprint=fp,
                verification_result="rolled_back",
                eligible_for_learning=False,
                eligibility_reason="rolled back",
                policy_version="playbook-v1",
                semantics_version="v2",
                limitations=[],
                workflow_status="current",
            )
        )
    db_session.commit()
    gate = verified_outcome_learning_service.fingerprint_attempt_gate(
        db_session,
        remediation_type="request_body_redaction",
        root_cause_category="unsafe_request_body_logging",
        sensitive_type="pan",
        exposure_location="application_logs",
        affected_component="logger",
    )
    assert gate["block_identical_auto_retry"] is True
    assert gate["human_review_required"] is True
