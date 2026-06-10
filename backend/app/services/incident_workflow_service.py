"""Single source of truth for incident workflow stage and next-action rules."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cicd_evidence import CicdEvidence
from app.models.audit_log import AuditLog
from app.models.detection import Detection
from app.models.enums import EvidenceType, ReviewDecisionType, VerificationStatus
from app.models.evidence_file import EvidenceFile
from app.models.fix_verification import FixVerification
from app.models.incident import Incident
from app.models.privacy_alert import PrivacyAlert
from app.models.remediation_action import RemediationAction
from app.models.report import Report
from app.models.review_decision import ReviewDecision
from app.models.root_cause_score import RootCauseScore
from app.models.scanner_evidence_record import ScannerEvidenceRecord
from app.schemas.incident_workflow_schema import (
    IncidentWorkflowState,
    WorkflowNextAction,
    WorkflowStage,
)
from app.services import (
    root_cause_analysis_service,
    root_cause_evidence_strength_service,
    workflow_provenance_service,
)
from app.services.remediation_action_service import remediation_is_complete


STAGE_LABELS = {
    "overview": "Overview",
    "root_cause": "Root Cause & Traceability",
    "human_review": "Human Review",
    "remediation": "Remediation",
    "fix_verification": "Fix Verification",
    "final_report": "Final Report",
}
STAGE_ROUTES = {
    "overview": "overview",
    "root_cause": "root-cause",
    "human_review": "review",
    "remediation": "remediation",
    "fix_verification": "verification",
    "final_report": "report",
}
FINAL_REVIEW_DECISIONS = {
    ReviewDecisionType.APPROVED.value,
    ReviewDecisionType.REQUEST_MORE_EVIDENCE.value,
    ReviewDecisionType.REJECTED_FALSE_POSITIVE.value,
    ReviewDecisionType.ESCALATED.value,
    ReviewDecisionType.REJECTED.value,
    ReviewDecisionType.INCONCLUSIVE.value,
}
FALSE_POSITIVE_DECISIONS = {
    ReviewDecisionType.REJECTED.value,
    ReviewDecisionType.REJECTED_FALSE_POSITIVE.value,
}
ESCALATED_DECISIONS = {
    ReviewDecisionType.INCONCLUSIVE.value,
    ReviewDecisionType.ESCALATED.value,
}


class IncidentWorkflowError(Exception):
    pass


class IncidentNotFoundError(IncidentWorkflowError):
    pass


@dataclass
class WorkflowFacts:
    incident: Incident
    linked_evidence_count: int
    root_cause_count: int
    root_strength: dict | None
    latest_review: ReviewDecision | None
    remediation_actions: list[RemediationAction]
    complete_remediation_actions: list[RemediationAction]
    retest_evidence_count: int
    latest_verification: FixVerification | None
    report_count: int

    @property
    def approved(self) -> bool:
        return bool(
            self.latest_review
            and self.latest_review.decision == ReviewDecisionType.APPROVED.value
        )

    @property
    def final_review_recorded(self) -> bool:
        return bool(
            self.latest_review and self.latest_review.decision in FINAL_REVIEW_DECISIONS
        )

    @property
    def false_positive(self) -> bool:
        return bool(
            self.latest_review and self.latest_review.decision in FALSE_POSITIVE_DECISIONS
        )


def _current_verification(db: Session, incident_id: str) -> FixVerification | None:
    return db.scalar(
        select(FixVerification)
        .where(
            FixVerification.incident_id == incident_id,
            FixVerification.workflow_status == "current",
        )
        .order_by(FixVerification.timestamp.desc(), FixVerification.id.desc())
        .limit(1)
    )


def collect_workflow_facts(db: Session, incident_id: str) -> WorkflowFacts:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")

    alerts = len(list(db.scalars(select(PrivacyAlert.id).where(PrivacyAlert.linked_incident_id == incident_id)).all()))
    detections = len(list(db.scalars(select(Detection.id).where(Detection.incident_id == incident_id)).all()))
    evidence = list(db.scalars(select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)).all())
    cicd = list(db.scalars(select(CicdEvidence).where(CicdEvidence.linked_incident_id == incident_id)).all())
    scanner_count = len(
        list(
            db.scalars(
                select(ScannerEvidenceRecord.id).where(
                    ScannerEvidenceRecord.linked_incident_id == incident_id
                )
            ).all()
        )
    )
    root_count = len(list(db.scalars(select(RootCauseScore.id).where(RootCauseScore.incident_id == incident_id)).all()))
    actions = list(
        db.scalars(
            select(RemediationAction)
            .where(RemediationAction.incident_id == incident_id)
            .order_by(RemediationAction.created_at.desc(), RemediationAction.id.desc())
        ).all()
    )
    retest_count = len(
        [item for item in evidence if item.evidence_type in {EvidenceType.FIXED_LOG, EvidenceType.FIXED_SCAN}]
    ) + len([item for item in cicd if item.evidence_type == "test_result"])
    generated_report_count = len(
        list(db.scalars(select(Report.id).where(Report.incident_id == incident_id)).all())
    )
    exported_report_count = len(
        list(
            db.scalars(
                select(AuditLog.id).where(
                    AuditLog.action == "report_exported",
                    AuditLog.target_type == "incident",
                    AuditLog.target_id == incident_id,
                )
            ).all()
        )
    )
    report_count = generated_report_count + exported_report_count
    linked_count = alerts + detections + len(evidence) + len(cicd) + scanner_count
    root_strength = (
        root_cause_evidence_strength_service.calculate_evidence_strength(db, incident_id)
        if linked_count or root_count
        else None
    )
    analysis = root_cause_analysis_service.get_current_analysis(db, incident_id)
    return WorkflowFacts(
        incident=incident,
        linked_evidence_count=linked_count,
        root_cause_count=root_count,
        root_strength=root_strength,
        latest_review=workflow_provenance_service.review_for_analysis(
            db, incident_id, analysis
        ),
        remediation_actions=actions,
        complete_remediation_actions=[item for item in actions if remediation_is_complete(item)],
        retest_evidence_count=retest_count,
        latest_verification=_current_verification(db, incident_id),
        report_count=report_count,
    )


def _stage(code: str, *, available: bool, completed: bool, blocked_reason: str | None = None) -> WorkflowStage:
    status = "complete" if completed else "ready" if available else "blocked"
    return WorkflowStage(
        code=code,
        label=STAGE_LABELS[code],
        status=status,
        available=available,
        completed=completed,
        blocked_reason=None if available or completed else blocked_reason,
    )


def _action(
    incident_id: str,
    code: str,
    label: str,
    description: str,
    stage: str,
    *,
    priority: str = "high",
    blocked: bool = False,
    blocked_reason: str | None = None,
) -> WorkflowNextAction:
    return WorkflowNextAction(
        code=code,
        label=label,
        description=description,
        target=f"/incidents/{incident_id}/{STAGE_ROUTES[stage]}",
        priority=priority,
        blocked=blocked,
        blocked_reason=blocked_reason,
    )


def get_workflow_state(db: Session, incident_id: str) -> IncidentWorkflowState:
    facts = collect_workflow_facts(db, incident_id)
    incident = facts.incident
    provenance = workflow_provenance_service.get_workflow_provenance_facts(db, incident_id)
    overview_complete = bool(incident.title and incident.summary and incident.status)
    root_available = facts.linked_evidence_count > 0
    analysis = root_cause_analysis_service.get_current_analysis(db, incident_id)
    root_complete = bool(
        analysis is not None
        and not bool(getattr(analysis, "stale", False))
        and facts.root_cause_count
        and facts.root_strength
        and facts.root_strength.get("confidence_cap_reason")
        and isinstance(facts.root_strength.get("missing_evidence"), list)
    )
    review_available = root_complete
    review_complete = bool(
        facts.final_review_recorded
        and facts.latest_review
        and facts.latest_review.progression_valid
        and analysis is not None
        and facts.latest_review.root_cause_analysis_id == analysis.analysis_id
    )
    remediation_blocked_by_stale = bool(provenance.get("blocked_reasons"))
    remediation_available = facts.approved and not remediation_blocked_by_stale
    remediation_complete = provenance.get("remediation_action_status") in {
        "awaiting_retest",
        "completed",
    }
    verification_available = bool(
        facts.approved
        and provenance.get("implementation_status") == "completed"
        and provenance.get("test_execution_status") == "passed"
        and provenance.get("controlled_retest_status") == "completed"
    )
    verification_complete = (
        str(provenance.get("verification_outcome") or "").casefold()
        == VerificationStatus.PASSED.value
    )
    unresolved_decisions = {
        ReviewDecisionType.REQUEST_MORE_EVIDENCE.value,
        *ESCALATED_DECISIONS,
    }
    report_requirements_met = bool(
        incident.summary
        and root_complete
        and review_complete
        and (not facts.approved or remediation_complete)
        and (not facts.approved or verification_complete)
        and not (
            facts.latest_review and facts.latest_review.decision in unresolved_decisions
        )
    )

    rem_blocked = (
        "; ".join(provenance["blocked_reasons"])
        if remediation_blocked_by_stale
        else "An approved human-review decision is required."
    )
    stages = [
        _stage("overview", available=True, completed=overview_complete),
        _stage(
            "root_cause",
            available=root_available,
            completed=root_complete,
            blocked_reason="Link an alert, detection, or supporting evidence item first.",
        ),
        _stage(
            "human_review",
            available=review_available,
            completed=review_complete,
            blocked_reason="Root Cause & Traceability must be completed first.",
        ),
        _stage(
            "remediation",
            available=remediation_available,
            completed=remediation_complete if facts.approved else facts.false_positive,
            blocked_reason=rem_blocked,
        ),
        _stage(
            "fix_verification",
            available=verification_available,
            completed=verification_complete if facts.approved else facts.false_positive,
            blocked_reason=(
                "An approved review, a remediation action awaiting retest, and retest evidence are required."
            ),
        ),
        _stage(
            "final_report",
            available=report_requirements_met,
            completed=facts.report_count > 0,
            blocked_reason="Required investigation stages are incomplete.",
        ),
    ]

    latest_decision = facts.latest_review.decision if facts.latest_review else None
    outcome_raw = str(provenance.get("verification_outcome") or "").casefold()
    if facts.linked_evidence_count == 0:
        next_action = _action(
            incident_id,
            "add_supporting_evidence",
            "Add Supporting Evidence",
            "Link masked evidence before root-cause analysis.",
            "root_cause",
        )
    elif not root_complete:
        next_action = _action(
            incident_id,
            "run_root_cause",
            "Run Root Cause & Traceability",
            "Rank likely causes and calculate evidence strength.",
            "root_cause",
        )
    elif not review_complete:
        next_action = _action(
            incident_id,
            "complete_human_review",
            "Complete Human Review",
            "Review the likely cause and supporting evidence.",
            "human_review",
        )
    elif latest_decision == ReviewDecisionType.REQUEST_MORE_EVIDENCE.value:
        next_action = _action(
            incident_id,
            "add_requested_evidence",
            "Add Requested Evidence",
            "Collect the evidence requested by the latest human review.",
            "root_cause",
        )
    elif latest_decision in ESCALATED_DECISIONS:
        next_action = _action(
            incident_id,
            "await_escalation_review",
            "Continue Escalation Review",
            "Assign or await an escalated human review decision.",
            "human_review",
            blocked=True,
            blocked_reason="An escalated human-review decision remains unresolved.",
        )
    elif latest_decision in FALSE_POSITIVE_DECISIONS and facts.report_count == 0:
        next_action = _action(
            incident_id,
            "review_incident_disposition",
            "Review Incident Disposition",
            "Document the false-positive decision and investigation limitations.",
            "final_report",
        )
    elif facts.approved and not remediation_complete:
        has_action = bool(facts.remediation_actions)
        next_action = _action(
            incident_id,
            "update_remediation" if has_action else "record_remediation",
            "Update Remediation Action" if has_action else "Record Remediation Action",
            "Save a human-owned remediation action and move it to awaiting retest.",
            "remediation",
        )
    elif facts.approved and facts.retest_evidence_count == 0:
        next_action = _action(
            incident_id,
            "add_retest_evidence",
            "Add Retest Evidence",
            "Link masked fixed-log, fixed-scan, or structured test evidence.",
            "fix_verification",
        )
    elif facts.approved and outcome_raw == VerificationStatus.FAILED.value:
        next_action = _action(
            incident_id,
            "update_remediation",
            "Update Remediation Action",
            "Revise the human-owned action before another retest.",
            "remediation",
        )
    elif facts.approved and outcome_raw == VerificationStatus.INCONCLUSIVE.value:
        next_action = _action(
            incident_id,
            "add_stronger_retest_evidence",
            "Add Stronger Retest Evidence",
            "Add clearer retest evidence before running verification again.",
            "fix_verification",
        )
    elif facts.approved and not verification_complete:
        next_action = _action(
            incident_id,
            "run_fix_verification",
            "Run Fix Verification",
            "Evaluate the available retest evidence.",
            "fix_verification",
        )
    elif facts.report_count == 0:
        next_action = _action(
            incident_id,
            "generate_final_report",
            "Generate Final Report",
            "Generate the privacy-safe investigation report.",
            "final_report",
        )
    else:
        next_action = _action(
            incident_id,
            "download_final_report",
            "Download Final Report",
            "Download the latest privacy-safe report.",
            "final_report",
            priority="medium",
        )

    current = next(
        (stage.code for stage in stages if not stage.completed and stage.available),
        "final_report",
    )
    from app.models.rollback_execution import RollbackExecution
    from app.services.remediation_lifecycle_service import derive_lifecycle_phase

    impl = None
    test = None
    retest = None
    outcome_row = None
    if provenance.get("implementation_id"):
        from app.models.workflow_verification import RemediationImplementationRecord

        impl = db.scalar(
            select(RemediationImplementationRecord).where(
                RemediationImplementationRecord.implementation_id
                == provenance["implementation_id"]
            )
        )
    if provenance.get("test_execution_id"):
        from app.models.workflow_verification import RemediationTestExecution

        test = db.scalar(
            select(RemediationTestExecution).where(
                RemediationTestExecution.execution_id == provenance["test_execution_id"]
            )
        )
    if provenance.get("controlled_retest_id"):
        from app.models.workflow_verification import ControlledRetest

        retest = db.scalar(
            select(ControlledRetest).where(
                ControlledRetest.controlled_retest_id == provenance["controlled_retest_id"]
            )
        )
    if provenance.get("verification_outcome_id"):
        from app.models.workflow_verification import VerificationOutcome

        outcome_row = db.scalar(
            select(VerificationOutcome).where(
                VerificationOutcome.verification_outcome_id
                == provenance["verification_outcome_id"]
            )
        )
    rollback = None
    if provenance.get("implementation_id"):
        rollback = db.scalar(
            select(RollbackExecution)
            .where(
                RollbackExecution.incident_id == incident_id,
                RollbackExecution.implementation_id == provenance["implementation_id"],
            )
            .order_by(RollbackExecution.id.desc())
            .limit(1)
        )
    lifecycle_phase = derive_lifecycle_phase(
        incident_status=incident.status.value,
        implementation=impl,
        test=test,
        retest=retest,
        outcome=outcome_row,
        rollback=rollback,
        learning_eligible=False,
    )
    return IncidentWorkflowState(
        incident_id=incident_id,
        current_stage=current,
        overall_status=incident.status.value,
        next_action=next_action,
        stages=stages,
        current_root_cause_analysis_id=provenance.get("current_root_cause_analysis_id"),
        current_root_cause_analysis_version=provenance.get(
            "current_root_cause_analysis_version"
        ),
        current_root_cause_analysis_stale=provenance.get("current_root_cause_analysis_stale"),
        workflow_chain_status=provenance.get("workflow_chain_status", "blocked"),
        review_progression_valid=provenance.get("review_progression_valid"),
        diagnosis_id=provenance.get("diagnosis_id"),
        diagnosis_generation_mode=provenance.get("diagnosis_generation_mode"),
        remediation_action_id=provenance.get("remediation_action_id"),
        remediation_action_status=provenance.get("remediation_action_status"),
        patch_status=provenance.get("patch_status"),
        test_execution_status=provenance.get("test_execution_status"),
        verification_outcome=provenance.get("verification_outcome"),
        blocked_reasons=list(provenance.get("blocked_reasons") or []),
        lifecycle_phase=lifecycle_phase,
    )
