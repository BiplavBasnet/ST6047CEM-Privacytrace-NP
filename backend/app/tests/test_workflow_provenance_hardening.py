"""Workflow provenance hardening — review/analysis binding, gates, learning fields."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.enums import ReviewDecisionType, VerificationStatus
from app.models.fix_verification import FixVerification
from app.models.remediation_action import RemediationAction
from app.models.review_decision import ReviewDecision
from app.models.root_cause_analysis import RootCauseAnalysis
from app.models.workflow_verification import VerificationOutcome
from app.services import (
    ai_remediation_diagnosis_service,
    controlled_patch_service,
    review_service,
    root_cause_analysis_service,
    verification_outcome_service,
    verified_outcome_learning_service,
    workflow_provenance_service,
)
from app.services.ai_remediation_diagnosis_service import DiagnosisGateError
from app.services.controlled_patch_service import ControlledPatchError
from app.services.workflow_provenance_service import WorkflowProvenanceError
from app.tests.ai_remediation_test_helpers import seed_active_analyst, seed_ai_incident

pytestmark = pytest.mark.usefixtures("migrated_db")


def _bind_approve(db, incident_id: str) -> ReviewDecision:
    analysis = root_cause_analysis_service.get_current_analysis(db, incident_id)
    assert analysis is not None
    review = ReviewDecision(
        incident_id=incident_id,
        decision=ReviewDecisionType.APPROVED.value,
        comment="Approved for provenance tests.",
        reason="Evidence supports progression.",
        evidence_checklist=["detections"],
        evidence_relied_on=["masked"],
        missing_evidence_acknowledged=True,
        root_cause_analysis_id=analysis.analysis_id,
        root_cause_analysis_version=analysis.analysis_version,
        evidence_snapshot_hash=analysis.evidence_snapshot_hash,
        progression_valid=True,
        submitted_at=datetime.now(timezone.utc),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(review)
    db.flush()
    return review


def _analyst(db) -> dict:
    user = seed_active_analyst(db)
    return {
        "actor_id": user.id,
        "actor_email": user.email,
        "actor_role": "security_analyst",
    }


def test_review_for_analysis_ignores_superseded_analysis_review(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-LATEST")
    current = root_cause_analysis_service.get_current_analysis(db_session, incident_id)
    assert current is not None
    current_review = _bind_approve(db_session, incident_id)
    later = datetime.now(timezone.utc)
    db_session.add(
        RootCauseAnalysis(
            analysis_id="RCA-SUPERSEDED",
            incident_id=incident_id,
            analysis_version=99,
            evidence_snapshot_hash="superseded-snapshot",
            current=False,
            stale=True,
            stale_reason="Superseded analysis for provenance test.",
            analysed_at=later,
        )
    )
    db_session.flush()
    db_session.add(
        ReviewDecision(
            incident_id=incident_id,
            decision=ReviewDecisionType.APPROVED.value,
            comment="Newer review bound to a superseded analysis.",
            reason="Must not become the current review.",
            evidence_checklist=["detections"],
            evidence_relied_on=["masked"],
            missing_evidence_acknowledged=True,
            root_cause_analysis_id="RCA-SUPERSEDED",
            root_cause_analysis_version=current.analysis_version + 1,
            evidence_snapshot_hash="superseded-snapshot",
            progression_valid=True,
            submitted_at=later,
            timestamp=later,
        )
    )
    db_session.flush()
    found = workflow_provenance_service.review_for_analysis(
        db_session, incident_id, current
    )
    assert found is not None
    assert found.id == current_review.id


def test_review_binds_to_current_analysis(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-REV")
    analysis = root_cause_analysis_service.get_current_analysis(db_session, incident_id)
    assert analysis is not None
    result = review_service.submit_review(
        db_session,
        incident_id,
        decision="approved",
        reason="Bind review to current analysis.",
        evidence_checklist=["detections"],
        missing_evidence_acknowledged=True,
    )
    assert result.review.root_cause_analysis_id == analysis.analysis_id
    assert result.review.evidence_snapshot_hash == analysis.evidence_snapshot_hash
    assert result.review.progression_valid is True
    assert result.review.submitted_at is not None


def test_stale_analysis_invalidates_progression(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-STALE")
    review = _bind_approve(db_session, incident_id)
    analysis = root_cause_analysis_service.get_current_analysis(db_session, incident_id)
    assert analysis is not None
    root_cause_analysis_service.mark_analysis_stale(
        db_session, analysis.analysis_id, "New evidence linked."
    )
    db_session.flush()
    db_session.refresh(review)
    assert review.progression_valid is False
    assert review.progression_invalid_reason
    with pytest.raises(WorkflowProvenanceError):
        workflow_provenance_service.assert_valid_review_for_remediation(db_session, incident_id)


def test_diagnosis_blocked_without_valid_review(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-GATE")
    with pytest.raises(DiagnosisGateError):
        ai_remediation_diagnosis_service.generate_problem_specific_remediation(
            db_session,
            incident_id,
            actor_id=None,
            actor_email="analyst@example.test",
            actor_role="security_analyst",
        )


def test_patch_requires_remediation_action(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-PATCH")
    _bind_approve(db_session, incident_id)
    analyst = seed_active_analyst(db_session)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        actor_id=analyst.id,
        actor_email=analyst.email,
        actor_role="security_analyst",
    )
    accepted = ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="accept",
        notes="ok",
        edited_primary=None,
        actor_id=analyst.id,
        actor_email=analyst.email,
        actor_role="security_analyst",
    )
    accepted.exact_source_location_known = True
    accepted.affected_file = "fixtures/gold_standard_wallet/request_logger.py"
    db_session.add(accepted)
    db_session.flush()
    with pytest.raises(ControlledPatchError):
        controlled_patch_service.generate_real_patch_proposal(
            db_session,
            accepted,
            remediation_action_id=None,
            actor_id=None,
            actor_email="analyst@example.test",
            actor_role="security_analyst",
        )


def test_learning_stores_canonical_taxonomy_fields(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-LRN")
    _bind_approve(db_session, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    primary = dict(row.primary_remediation or {})
    primary["sensitive_type"] = "nepal_phone"
    primary["exposure_location"] = "application_log"
    primary["root_cause_category"] = "logging_redaction_gap"
    row.primary_remediation = primary
    db_session.add(row)
    db_session.flush()
    ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="accept",
        notes="ok",
        edited_primary=None,
        **_analyst(db_session),
    )
    fv = FixVerification(
        incident_id=incident_id,
        verification_status=VerificationStatus.PASSED,
        checks_run=["retest"],
        passed_checks=["no_raw"],
        failed_checks=[],
        evidence_used=[],
    )
    db_session.add(fv)
    db_session.flush()
    outcome = verified_outcome_learning_service.record_verified_outcome(
        db_session,
        incident_id=incident_id,
        diagnosis_id=row.diagnosis_id,
        verification_id=str(fv.id),
        sensitive_type="nepal_phone",
        exposure_location="application_log",
        root_cause_category="logging_redaction_gap",
    )
    assert outcome["sensitive_type"] == "nepal_phone"
    assert outcome["exposure_location"] == "application_log"
    assert outcome["root_cause_category"] == "logging_redaction_gap"
    assert outcome["sensitive_type"] != row.problem_statement


def test_verification_outcome_persists(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-VO")
    _bind_approve(db_session, incident_id)
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
    fv = FixVerification(
        incident_id=incident_id,
        verification_status=VerificationStatus.PASSED,
        checks_run=["retest"],
        passed_checks=["ok"],
        failed_checks=[],
        evidence_used=[],
    )
    db_session.add(fv)
    db_session.flush()
    built = verification_outcome_service.build_verification_outcome(
        db_session,
        incident_id=incident_id,
        diagnosis=row,
        verification=fv,
        test_result={"passed": True, "raw_value_leakage_result": 0},
        verified_by="analyst@example.test",
    )
    assert built["verification_outcome_id"]
    persisted = db_session.scalar(
        select(VerificationOutcome).where(
            VerificationOutcome.verification_outcome_id == built["verification_outcome_id"]
        )
    )
    assert persisted is not None
    assert persisted.verification_result == "passed"
    assert persisted.eligible_for_learning is False
    assert "controlled-retest" in (persisted.eligibility_reason or "").lower()


def test_double_accept_returns_same_remediation_action(db_session):
    incident_id = seed_ai_incident(db_session, incident_id="INC-PROV-IDEMP")
    _bind_approve(db_session, incident_id)
    row, _ = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
        db_session,
        incident_id,
        **_analyst(db_session),
    )
    first = ai_remediation_diagnosis_service.review_diagnosis(
        db_session,
        row.diagnosis_id,
        decision="accept",
        notes="ok",
        edited_primary=None,
        **_analyst(db_session),
    )
    action1 = db_session.scalar(
        select(RemediationAction).where(RemediationAction.diagnosis_id == first.diagnosis_id)
    )
    assert action1 is not None
    # Second call to create path (idempotent helper)
    action2 = ai_remediation_diagnosis_service._create_action_from_accepted_diagnosis(
        db_session, first, actor_id=None
    )
    assert action2.remediation_action_id == action1.remediation_action_id
    count = len(
        list(
            db_session.scalars(
                select(RemediationAction).where(
                    RemediationAction.diagnosis_id == first.diagnosis_id
                )
            ).all()
        )
    )
    assert count == 1


def test_detection_fingerprint_never_falls_back_to_sha256(db_session, monkeypatch):
    """AA: detection creation must not write unkeyed sha256: fingerprints."""

    from app.models import Detection, EvidenceFile, NormalizedEvent
    from app.models.enums import EvidenceType, ParsingStatus, Severity
    from app.services import detection_service, sensitive_fingerprint_service as fps

    monkeypatch.setattr(
        "app.services.sensitive_fingerprint_service.get_settings",
        lambda: type("S", (), {"detection_hmac_key": "test-hmac-key-for-aa"})(),
    )
    evidence = EvidenceFile(
        evidence_id="EVD-HMAC-AA",
        file_name="aa.log",
        evidence_type=EvidenceType.API_LOG,
        source_system="test",
        file_hash="sha256:" + ("a" * 64),
        parsing_status=ParsingStatus.PARSED,
        linked_incident_id=None,
    )
    db_session.add(evidence)
    event = NormalizedEvent(
        event_id="EVT-HMAC-AA",
        evidence_id=evidence.evidence_id,
        timestamp=datetime.now(timezone.utc),
        source_type="application_log",
        service_name="wallet-service",
        endpoint="/wallet/transfer",
        event_type="log",
        masked_message="phone 9841234567",
        severity=Severity.HIGH,
    )
    db_session.add(event)
    db_session.flush()
    # Force engine path via detect_event when possible; also unit-check helper.
    fp = detection_service.fingerprint_for_detection("9841234567", "nepal_phone")
    assert fp is not None
    assert fp.startswith("HMAC-SHA256-V1:")
    assert not fps.is_legacy_sha256(fp)
    monkeypatch.setattr(
        "app.services.sensitive_fingerprint_service.get_settings",
        lambda: type("S", (), {"detection_hmac_key": ""})(),
    )
    assert detection_service.fingerprint_for_detection("9841234567", "nepal_phone") is None


def test_unique_trace_count_uses_alert_trace_reference(db_session):
    """X/Y: affected_trace_count = distinct known traces; no fabrication."""

    from app.models.privacy_alert import PrivacyAlert
    from app.models.enums import Severity
    from app.services import correlation_fingerprint_service, live_alert_grouping_service

    alert = PrivacyAlert(
        alert_id="LPA-TRACE-UNIQUE",
        alert_time=datetime.now(timezone.utc),
        source_type="api_log",
        source_format="generic_json",
        severity=Severity.HIGH,
        status="new",
        sensitive_types=["nepal_phone"],
        masked_values=["984****567"],
        detection_ids=[],
        raw_event_hash="sha256:" + ("c" * 64),
        safety_status="safe",
        alert_summary="test",
        alert_group_key="AGRP-test-unique-trace",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        repeat_count=1,
        affected_trace_count=None,
        trace_count_quality="unavailable",
    )
    db_session.add(alert)
    db_session.flush()

    live_alert_grouping_service.record_trace_reference(db_session, alert, trace_fingerprint=None)
    assert alert.affected_trace_count is None
    assert alert.trace_count_quality == "unavailable"

    trace_a = correlation_fingerprint_service.fingerprint("trace-A", "trace_id")
    trace_b = correlation_fingerprint_service.fingerprint("trace-B", "trace_id")
    assert trace_a and trace_b
    live_alert_grouping_service.record_trace_reference(
        db_session, alert, trace_fingerprint=trace_a["fingerprint"]
    )
    assert alert.affected_trace_count == 1
    assert alert.trace_count_quality == "exact"
    live_alert_grouping_service.record_trace_reference(
        db_session, alert, trace_fingerprint=trace_a["fingerprint"]
    )
    assert alert.affected_trace_count == 1
    live_alert_grouping_service.record_trace_reference(
        db_session, alert, trace_fingerprint=trace_b["fingerprint"]
    )
    assert alert.affected_trace_count == 2

    live_alert_grouping_service.register_recurrence(
        db_session,
        alert,
        observed_at=datetime.now(timezone.utc),
        source_event_time=datetime.now(timezone.utc),
        trace_fingerprint=None,
    )
    assert alert.repeat_count == 2
    assert alert.affected_trace_count == 2
