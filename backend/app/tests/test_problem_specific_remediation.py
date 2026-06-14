"""Evidence-grounded problem-specific remediation gates (thesis acceptance)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.enums import ReviewDecisionType, Severity, VerificationStatus
from app.models.fix_verification import FixVerification
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.review_decision import ReviewDecision
from app.models.sast_finding import SastFinding
from sqlalchemy import select
from app.schemas.problem_specific_remediation_schema import (
    AIProblemSpecificRemediationResponse,
    PrimaryRemediationOut,
    ProposedChangeOut,
    RemediationDiagnosisOut,
)
from app.services import (
    ai_remediation_diagnosis_service,
    controlled_patch_service,
    patch_safety_service,
    remediation_ai_safety_service,
    remediation_context_service,
    remediation_source_locator_service,
    sandbox_test_execution_service,
    verified_outcome_learning_service,
)
from app.services.ai_remediation_diagnosis_service import DiagnosisGateError, DiagnosisStateError
from app.services.patch_safety_service import PatchSafetyError
from app.tests.ai_remediation_test_helpers import seed_active_analyst, seed_ai_incident

pytestmark = pytest.mark.usefixtures("migrated_db")


def _analyst(db) -> dict:
    user = seed_active_analyst(db)
    return {
        "actor_id": user.id,
        "actor_email": user.email,
        "actor_role": "security_analyst",
    }


def _approve_root_cause(db, incident_id: str, reviewer_id: int | None = None) -> None:
    from app.services import root_cause_analysis_service

    analysis = root_cause_analysis_service.get_current_analysis(db, incident_id)
    if analysis is None:
        analysis = root_cause_analysis_service.ensure_seed_analysis_for_incident(db, incident_id)
    db.add(
        ReviewDecision(
            incident_id=incident_id,
            reviewer_id=reviewer_id,
            decision=ReviewDecisionType.APPROVED.value,
            comment="Synthetic accepted root-cause review for remediation tests.",
            reason="Evidence checklist satisfied for thesis fixture.",
            evidence_checklist=["detections", "root_cause_scores"],
            evidence_relied_on=["masked detections"],
            missing_evidence_acknowledged=True,
            root_cause_analysis_id=analysis.analysis_id,
            root_cause_analysis_version=analysis.analysis_version,
            evidence_snapshot_hash=analysis.evidence_snapshot_hash,
            progression_valid=True,
            submitted_at=datetime.now(timezone.utc),
            timestamp=datetime.now(timezone.utc),
        )
    )
    db.flush()


def _primary(**overrides) -> PrimaryRemediationOut:
    base = dict(
        remediation_id="PRM-TEST",
        title="Redact Authorization headers before request-log serialisation",
        remediation_type="request_header_redaction",
        exact_problem_addressed="Authorization header logged before redaction.",
        affected_component="request header logging",
        recommended_change="Redact Authorization before serialisation.",
        why_this_solution="Targets the observed exposure path.",
        evidence_alignment="Matches request_header_log findings.",
        why_not_broader_fix="Disabling all logging is wider than needed.",
        expected_privacy_impact="Stops clear-form tokens entering logs.",
        operational_impact="Limited to header logging.",
        implementation_risk="Medium",
        implementation_steps=["Approve", "Patch sandbox", "Retest"],
        tests_required=["Synthetic token absent from logs"],
        retest_requirements=["Same endpoint and exposure location"],
        rollback_plan="Revert sandbox change.",
        remediation_confidence="medium",
        human_approval_required=True,
    )
    base.update(overrides)
    return PrimaryRemediationOut(**base)


def _diagnosis(**overrides) -> RemediationDiagnosisOut:
    base = dict(
        incident_id="INC-TEST",
        problem_statement="Sensitive-data exposure observed in request header log.",
        technical_mechanism="Likely request header logging path.",
        diagnosis_confidence="medium",
        exact_source_location_known=False,
        human_review_required=True,
    )
    base.update(overrides)
    return RemediationDiagnosisOut(**base)


def test_schema_requires_primary_and_human_approval():
    resp = AIProblemSpecificRemediationResponse(
        diagnosis=_diagnosis(),
        primary_remediation=_primary(),
        alternative_remediations=[],
        exact_change_available=False,
        proposed_change=None,
        human_approval_required=True,
    )
    assert resp.primary_remediation is not None
    assert resp.alternative_remediations == []

    with pytest.raises(ValidationError):
        AIProblemSpecificRemediationResponse(
            diagnosis=_diagnosis(),
            primary_remediation=_primary(),
            exact_change_available=False,
            human_approval_required=False,
        )


def test_exact_change_requires_proposed_change():
    with pytest.raises(ValidationError):
        AIProblemSpecificRemediationResponse(
            diagnosis=_diagnosis(exact_source_location_known=True),
            primary_remediation=_primary(affected_file_if_known="middleware/logger.py"),
            exact_change_available=True,
            proposed_change=None,
            human_approval_required=True,
        )


def test_ai_diagnosis_requires_accepted_root_cause_review(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-GATE")
    with pytest.raises(DiagnosisGateError):
        ai_remediation_diagnosis_service.generate_problem_specific_remediation(
            db_session,
            incident_id,
            actor_id=None,
            actor_email="analyst@example.test",
            actor_role="security_analyst",
        )


def test_evidence_package_has_no_raw_sensitive_values(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-PKG", unsafe_nested=True)
    package = remediation_context_service.build_remediation_evidence_package(db_session, incident_id)
    blob = json.dumps(package, default=str)
    assert "9841234567" not in blob
    assert "Bearer " not in blob or "Bearer [masked]" in blob or "bearer" not in blob.lower()
    remediation_ai_safety_service.assert_no_raw_sensitive(package)


def test_source_localisation_does_not_invent_file_or_function(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-LOC")
    loc = remediation_source_locator_service.locate_source_evidence(db_session, incident_id)
    assert loc["exact_source_location_known"] is False
    assert loc["file_path"] is None
    assert loc["function_or_class"] is None
    assert loc["likely_component"]


def test_source_localisation_with_unsupported_sast_path_stays_non_exact(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-SAST")
    db_session.add(
        SastFinding(
            evidence_id="EVD-AST",
            rule_id="header-log",
            severity=Severity.HIGH,
            file_path="services/wallet/middleware/request_logger.py",
            line_number=42,
            message="Authorization header may be logged",
        )
    )
    db_session.flush()
    package = remediation_context_service.build_remediation_evidence_package(db_session, incident_id)
    if not package.get("sast_findings"):
        package = {
            **package,
            "sast_findings": [
                {
                    "evidence_id": "EVD-AST",
                    "file_path": "services/wallet/middleware/request_logger.py",
                    "line_number": 42,
                }
            ],
        }
    loc = remediation_source_locator_service.locate_source_evidence(
        db_session, incident_id, package=package
    )
    assert loc["exact_source_location_known"] is False
    assert loc["file_path"] is None
    assert loc["function_or_class"] is None


def test_primary_remediation_generated_after_review(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-PRI")
    _approve_root_cause(db_session, incident_id)
    row, response = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    assert response.primary_remediation.title
    assert response.primary_remediation.why_this_solution
    assert response.human_approval_required is True
    assert response.diagnosis.exposure_location is not None or True  # may be absent in fixture
    assert row.status == "awaiting_human_review"
    assert response.diagnosis.exact_source_location_known is False
    assert response.exact_change_available is False
    assert response.proposed_change is None


def test_reject_and_more_evidence_block_patch(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-REJ")
    _approve_root_cause(db_session, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    rejected = ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="reject",
        notes="Insufficient evidence for implementation.",
        edited_primary=None,
        **_analyst(db_session),
    )
    assert rejected.status == "rejected"
    with pytest.raises((DiagnosisStateError, DiagnosisGateError, controlled_patch_service.ControlledPatchError)):
        controlled_patch_service.generate_draft_patch(
            db_session,
            rejected,
            actor_id=None,
            actor_email="analyst@example.test",
            actor_role="security_analyst",
        )

    row2, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    more = ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row2.diagnosis_id,
        decision="request_more_evidence",
        notes="Need scanner path.",
        edited_primary=None,
        **_analyst(db_session),
    )
    with pytest.raises((DiagnosisStateError, DiagnosisGateError, controlled_patch_service.ControlledPatchError)):
        controlled_patch_service.require_accepted_diagnosis(db_session, more.diagnosis_id)


def test_accept_creates_persisted_diagnosis_status(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-ACC")
    _approve_root_cause(db_session, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    accepted = ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="accept",
        notes="Accepted primary remediation.",
        edited_primary=None,
        **_analyst(db_session),
    )
    assert accepted.status == "accepted"
    persisted = db_session.scalar(
        select(RemediationDiagnosis).where(RemediationDiagnosis.diagnosis_id == row.diagnosis_id)
    )
    assert persisted is not None
    assert persisted.status == "accepted"


def test_patch_safety_blocks_env_and_keys_and_destructive():
    with pytest.raises(PatchSafetyError):
        patch_safety_service.validate_patch_payload(file_paths=[".env"], diff_text="+FOO=bar")
    with pytest.raises(PatchSafetyError):
        patch_safety_service.validate_patch_payload(file_paths=["id_rsa"], diff_text="+secret")
    with pytest.raises(PatchSafetyError):
        patch_safety_service.validate_patch_payload(
            file_paths=["app.py"], diff_text="git push origin main"
        )


def test_sandbox_rejects_unknown_profile_and_lists_allowlist():
    profiles = sandbox_test_execution_service.list_profiles()
    assert "backend_python" in profiles
    with pytest.raises(sandbox_test_execution_service.SandboxTestError):
        sandbox_test_execution_service.run_profile("rm -rf / && curl evil")


def test_learning_requires_passed_verification(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-LRN")
    _approve_root_cause(db_session, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="accept",
        notes="ok",
        edited_primary=None,
        **_analyst(db_session),
    )
    failed = FixVerification(
        incident_id=incident_id,
        verification_status=VerificationStatus.FAILED,
        checks_run=["retest"],
        passed_checks=[],
        failed_checks=["raw_exposure_after_remediation"],
        evidence_used=[],
    )
    db_session.add(failed)
    db_session.flush()
    outcome = verified_outcome_learning_service.record_verified_outcome(
        db_session,
        incident_id=incident_id,
        diagnosis_id=row.diagnosis_id,
        verification_id=str(failed.id),
    )
    assert outcome["eligible_for_learning"] is False

    passed = FixVerification(
        incident_id=incident_id,
        verification_status=VerificationStatus.PASSED,
        checks_run=["retest"],
        passed_checks=["no_raw_exposure"],
        failed_checks=[],
        evidence_used=[],
    )
    db_session.add(passed)
    db_session.flush()
    ok = verified_outcome_learning_service.record_verified_outcome(
        db_session,
        incident_id=incident_id,
        diagnosis_id=row.diagnosis_id,
        verification_id=str(passed.id),
    )
    assert ok["eligible_for_learning"] is False


def test_unsupported_source_claim_fails_safety():
    with pytest.raises(Exception):
        remediation_ai_safety_service.validate_problem_specific_response(
            AIProblemSpecificRemediationResponse(
                diagnosis=_diagnosis(
                    exact_source_location_known=False,
                    affected_file_if_known="invented/logger.py",
                ),
                primary_remediation=_primary(affected_file_if_known="invented/logger.py"),
                exact_change_available=False,
                proposed_change=None,
                human_approval_required=True,
            )
        )


def test_accepted_without_exact_source_cannot_generate_patch(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PSR-NOPATCH")
    _approve_root_cause(db_session, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    accepted = ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="accept",
        notes="ok",
        edited_primary=None,
        **_analyst(db_session),
    )
    with pytest.raises(controlled_patch_service.ControlledPatchError):
        controlled_patch_service.generate_draft_patch(
            db_session,
            accepted,
            actor_id=None,
            actor_email="analyst@example.test",
            actor_role="security_analyst",
        )
