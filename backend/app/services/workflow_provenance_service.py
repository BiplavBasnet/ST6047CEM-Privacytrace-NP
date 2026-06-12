"""Authoritative governed-remediation permission and reference traversal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.models.enums import ReviewDecisionType
from app.models.incident import Incident
from app.models.remediation_action import RemediationAction
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.review_decision import ReviewDecision
from app.models.root_cause_analysis import RootCauseAnalysis
from app.models.user import User
from app.models.verified_remediation_learning import PatchProposal
from app.models.workflow_verification import (
    ControlledRetest,
    RemediationImplementationRecord,
    RemediationTestExecution,
    VerificationOutcome,
)
from app.models.fix_verification import FixVerification
from app.services import root_cause_analysis_service


class WorkflowProvenanceError(Exception):
    """A governed transition is not bound to the current approved chain."""


@dataclass(frozen=True)
class ValidReviewContext:
    incident: Incident
    review: ReviewDecision
    analysis: RootCauseAnalysis
    actor: User | None = None
    diagnosis: RemediationDiagnosis | None = None
    action: RemediationAction | None = None

    @property
    def analysis_id(self) -> str:
        return self.analysis.analysis_id

    @property
    def analysis_version(self) -> int:
        return self.analysis.analysis_version

    @property
    def evidence_snapshot_hash(self) -> str:
        return self.analysis.evidence_snapshot_hash


def review_for_analysis(
    db: Session, incident_id: str, analysis: RootCauseAnalysis | None
) -> ReviewDecision | None:
    """Current-analysis review only — never the latest review of a superseded analysis."""
    if analysis is None:
        return None
    return db.scalar(
        select(ReviewDecision)
        .where(
            ReviewDecision.incident_id == incident_id,
            ReviewDecision.root_cause_analysis_id == analysis.analysis_id,
            ReviewDecision.root_cause_analysis_version == analysis.analysis_version,
            ReviewDecision.evidence_snapshot_hash == analysis.evidence_snapshot_hash,
        )
        .order_by(ReviewDecision.timestamp.desc(), ReviewDecision.id.desc())
        .limit(1)
    )


def _latest_review(db: Session, incident_id: str) -> ReviewDecision | None:
    """History helper. Governed transitions must use review_for_analysis."""
    return review_for_analysis(
        db, incident_id, root_cause_analysis_service.get_current_analysis(db, incident_id)
    )


def assert_current_governed_remediation_permission(
    db: Session,
    incident_id: str,
    *,
    actor_id: int | None = None,
    require_active_human_actor: bool = False,
    root_cause_analysis_id: str | None = None,
    root_cause_analysis_version: int | None = None,
    evidence_snapshot_hash: str | None = None,
    review_decision_id: int | None = None,
    diagnosis_id: str | None = None,
    remediation_action_id: str | None = None,
) -> ValidReviewContext:
    """Resolve one current RCA/review chain and validate optional descendants.

    User rows are the application's human identities. Approval/action boundaries
    set ``require_active_human_actor`` so null, missing, and inactive actors fail.
    """
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise WorkflowProvenanceError(f"Incident not found: {incident_id}")

    analysis = root_cause_analysis_service.ensure_current_analysis(db, incident_id)
    if analysis is None:
        latest = root_cause_analysis_service.get_latest_analysis(db, incident_id)
        if latest is not None and (latest.stale or not latest.current):
            raise WorkflowProvenanceError(
                "Root-cause analysis is stale or superseded; re-analyse before remediation."
            )
        raise WorkflowProvenanceError(
            "No current root-cause analysis; run POST /incidents/analyse first."
        )
    if analysis.stale or not analysis.current:
        raise WorkflowProvenanceError(
            "Current root-cause analysis is stale; re-analyse before remediation."
        )

    expected_analysis_id = root_cause_analysis_id or analysis.analysis_id
    expected_version = root_cause_analysis_version or analysis.analysis_version
    expected_snapshot = evidence_snapshot_hash or analysis.evidence_snapshot_hash
    if (
        expected_analysis_id != analysis.analysis_id
        or expected_version != analysis.analysis_version
        or expected_snapshot != analysis.evidence_snapshot_hash
    ):
        raise WorkflowProvenanceError(
            "Transition is not bound to the current root-cause analysis version and evidence snapshot."
        )

    review = review_for_analysis(db, incident_id, analysis)
    if review is None or str(review.decision).lower() != ReviewDecisionType.APPROVED.value:
        raise WorkflowProvenanceError(
            "A current approved human root-cause review is required before remediation."
        )
    if not review.progression_valid:
        raise WorkflowProvenanceError(
            review.progression_invalid_reason
            or "Review progression is invalid; re-submit review against the current analysis."
        )
    if (
        review.root_cause_analysis_id != analysis.analysis_id
        or review.root_cause_analysis_version != analysis.analysis_version
        or review.evidence_snapshot_hash != analysis.evidence_snapshot_hash
    ):
        raise WorkflowProvenanceError(
            "Review is not bound to the current root-cause analysis version and evidence snapshot."
        )
    if review_decision_id is not None and review.id != review_decision_id:
        raise WorkflowProvenanceError("Transition is not bound to the current approved review.")

    actor = None
    if require_active_human_actor:
        actor = db.get(User, actor_id) if actor_id is not None else None
        if actor is None or not actor.is_active:
            raise WorkflowProvenanceError(
                "An active human user is required for this governed transition."
            )

    diagnosis = None
    action = None
    if remediation_action_id is not None:
        action = db.scalar(
            select(RemediationAction).where(
                RemediationAction.remediation_action_id == remediation_action_id
            )
        )
        if action is None:
            raise WorkflowProvenanceError(
                f"Remediation action not found: {remediation_action_id}"
            )
        if diagnosis_id is None:
            diagnosis_id = action.diagnosis_id

    if diagnosis_id is not None:
        diagnosis = db.scalar(
            select(RemediationDiagnosis).where(
                RemediationDiagnosis.diagnosis_id == diagnosis_id
            )
        )
        if diagnosis is None:
            raise WorkflowProvenanceError(f"Remediation diagnosis not found: {diagnosis_id}")
        if (
            diagnosis.incident_id != incident_id
            or diagnosis.root_cause_analysis_id != analysis.analysis_id
            or diagnosis.root_cause_analysis_version != analysis.analysis_version
            or diagnosis.evidence_snapshot_hash != analysis.evidence_snapshot_hash
            or diagnosis.review_decision_id != review.id
            or diagnosis.derived_from_stale_analysis
            or diagnosis.workflow_status != "current"
        ):
            raise WorkflowProvenanceError(
                "Remediation diagnosis is stale or does not belong to the current approved chain."
            )

    if action is not None:
        if (
            action.incident_id != incident_id
            or action.root_cause_analysis_id != analysis.analysis_id
            or action.review_decision_id != review.id
            or action.requires_revalidation
            or getattr(action, "workflow_status", "current") != "current"
            or (diagnosis is not None and action.diagnosis_id != diagnosis.diagnosis_id)
        ):
            raise WorkflowProvenanceError(
                "Remediation action is stale or does not belong to the current approved chain."
            )

    return ValidReviewContext(
        incident=incident,
        review=review,
        analysis=analysis,
        actor=actor,
        diagnosis=diagnosis,
        action=action,
    )


def assert_valid_review_for_remediation(db: Session, incident_id: str) -> ValidReviewContext:
    """Backward-compatible name for read-only diagnosis generation gates."""
    return assert_current_governed_remediation_permission(db, incident_id)


def get_workflow_provenance_facts(db: Session, incident_id: str) -> dict[str, Any]:
    """Traverse the current chain by stored references; never compose latest rows."""
    current = root_cause_analysis_service.get_current_analysis(db, incident_id)
    latest = current or root_cause_analysis_service.get_latest_analysis(db, incident_id)
    review = review_for_analysis(db, incident_id, current or latest)
    blocked_reasons: list[str] = []
    chain_status = "blocked"
    context: ValidReviewContext | None = None

    if latest is None:
        blocked_reasons.append("No current root-cause analysis is available.")
    elif current is None or latest.stale or not latest.current:
        chain_status = "stale"
        blocked_reasons.append(
            latest.stale_reason or "Root-cause analysis is stale or superseded; re-analysis is required."
        )
    else:
        try:
            context = assert_current_governed_remediation_permission(db, incident_id)
            chain_status = "current"
        except WorkflowProvenanceError as exc:
            blocked_reasons.append(str(exc))

    diagnosis = None
    action = None
    patch = None
    implementation = None
    test_exec = None
    controlled_retest = None
    outcome = None
    if context is not None:
        diagnosis = db.scalar(
            select(RemediationDiagnosis)
            .where(
                RemediationDiagnosis.incident_id == incident_id,
                RemediationDiagnosis.root_cause_analysis_id == context.analysis_id,
                RemediationDiagnosis.root_cause_analysis_version == context.analysis_version,
                RemediationDiagnosis.evidence_snapshot_hash == context.evidence_snapshot_hash,
                RemediationDiagnosis.review_decision_id == context.review.id,
                RemediationDiagnosis.derived_from_stale_analysis.is_(False),
                RemediationDiagnosis.workflow_status == "current",
            )
            .order_by(
                case((RemediationDiagnosis.status.in_(("accepted", "accepted_with_edits")), 0), else_=1),
                RemediationDiagnosis.created_at.desc(), RemediationDiagnosis.id.desc(),
            )
            .limit(1)
        )
        if diagnosis is not None:
            action = db.scalar(
                select(RemediationAction)
                .where(
                    RemediationAction.incident_id == incident_id,
                    RemediationAction.diagnosis_id == diagnosis.diagnosis_id,
                    RemediationAction.root_cause_analysis_id == context.analysis_id,
                    RemediationAction.review_decision_id == context.review.id,
                    RemediationAction.requires_revalidation.is_(False),
                    RemediationAction.workflow_status == "current",
                )
                .order_by(RemediationAction.created_at.desc(), RemediationAction.id.desc())
                .limit(1)
            )
        if action is None:
            action = db.scalar(
                select(RemediationAction)
                .where(
                    RemediationAction.incident_id == incident_id,
                    RemediationAction.diagnosis_id.is_(None),
                    RemediationAction.root_cause_analysis_id == context.analysis_id,
                    RemediationAction.review_decision_id == context.review.id,
                    RemediationAction.requires_revalidation.is_(False),
                    RemediationAction.workflow_status == "current",
                )
                .order_by(RemediationAction.created_at.desc(), RemediationAction.id.desc())
                .limit(1)
            )
        if action is not None:
            patch = db.scalar(
                select(PatchProposal)
                .where(
                    PatchProposal.incident_id == incident_id,
                    PatchProposal.remediation_action_id == action.remediation_action_id,
                    PatchProposal.root_cause_analysis_id == context.analysis_id,
                    PatchProposal.workflow_status == "current",
                )
                .order_by(PatchProposal.created_at.desc(), PatchProposal.id.desc())
                .limit(1)
            )
            implementation = db.scalar(
                select(RemediationImplementationRecord)
                .where(
                    RemediationImplementationRecord.incident_id == incident_id,
                    RemediationImplementationRecord.remediation_action_id
                    == action.remediation_action_id,
                    RemediationImplementationRecord.root_cause_analysis_id
                    == context.analysis_id,
                    RemediationImplementationRecord.review_decision_id
                    == context.review.id,
                    RemediationImplementationRecord.workflow_status == "current",
                )
                .order_by(RemediationImplementationRecord.created_at.desc())
                .limit(1)
            )
            test_exec = db.scalar(
                select(RemediationTestExecution)
                .where(
                    RemediationTestExecution.incident_id == incident_id,
                    RemediationTestExecution.remediation_action_id
                    == action.remediation_action_id,
                    RemediationTestExecution.implementation_id
                    == (implementation.implementation_id if implementation else None),
                    RemediationTestExecution.workflow_status == "current",
                )
                .order_by(RemediationTestExecution.created_at.desc(), RemediationTestExecution.id.desc())
                .limit(1)
            )
        if test_exec is not None and implementation is not None:
            controlled_retest = db.scalar(
                select(ControlledRetest)
                .where(
                    ControlledRetest.incident_id == incident_id,
                    ControlledRetest.implementation_id
                    == implementation.implementation_id,
                    ControlledRetest.test_execution_id == test_exec.execution_id,
                    ControlledRetest.workflow_status == "current",
                )
                .order_by(ControlledRetest.created_at.desc())
                .limit(1)
            )
        if test_exec is not None:
            outcome = db.scalar(
                select(VerificationOutcome)
                .where(
                    VerificationOutcome.incident_id == incident_id,
                    VerificationOutcome.root_cause_analysis_id == context.analysis_id,
                    VerificationOutcome.review_decision_id == context.review.id,
                    VerificationOutcome.remediation_diagnosis_id
                    == (diagnosis.diagnosis_id if diagnosis else None),
                    VerificationOutcome.remediation_action_id
                    == (action.remediation_action_id if action else None),
                    VerificationOutcome.test_execution_id == test_exec.execution_id,
                    VerificationOutcome.implementation_id
                    == (implementation.implementation_id if implementation else None),
                    VerificationOutcome.controlled_retest_id
                    == (
                        controlled_retest.controlled_retest_id
                        if controlled_retest
                        else None
                    ),
                    VerificationOutcome.workflow_status == "current",
                )
                .order_by(VerificationOutcome.created_at.desc(), VerificationOutcome.id.desc())
                .limit(1)
            )

    return {
        "workflow_chain_status": chain_status,
        "current_root_cause_analysis_id": latest.analysis_id if latest else None,
        "current_root_cause_analysis_version": latest.analysis_version if latest else None,
        "current_root_cause_analysis_stale": (
            bool(latest.stale or not latest.current) if latest else None
        ),
        "review_progression_valid": bool(review.progression_valid) if review else None,
        "review_decision_id": context.review.id if context else None,
        "diagnosis_id": diagnosis.diagnosis_id if diagnosis else None,
        "diagnosis_generation_mode": diagnosis.generation_mode if diagnosis else None,
        "remediation_action_id": action.remediation_action_id if action else None,
        "remediation_action_status": action.status if action else None,
        "patch_status": patch.status if patch else None,
        "implementation_id": implementation.implementation_id if implementation else None,
        "implementation_status": implementation.status if implementation else None,
        "test_execution_status": test_exec.status if test_exec else None,
        "test_execution_id": test_exec.execution_id if test_exec else None,
        "controlled_retest_id": (
            controlled_retest.controlled_retest_id if controlled_retest else None
        ),
        "controlled_retest_status": controlled_retest.status if controlled_retest else None,
        "verification_outcome": outcome.verification_result if outcome else None,
        "verification_outcome_id": outcome.verification_outcome_id if outcome else None,
        "blocked_reasons": blocked_reasons,
    }


def get_exact_report_chain(db: Session, incident_id: str) -> dict[str, Any]:
    """Resolve one report chain from the current provenance outcome, then exact FKs."""

    facts = get_workflow_provenance_facts(db, incident_id)
    outcome = None
    if facts.get("verification_outcome_id"):
        outcome = db.scalar(
            select(VerificationOutcome).where(
                VerificationOutcome.verification_outcome_id
                == facts["verification_outcome_id"]
            )
        )
    fix = (
        db.get(FixVerification, outcome.fix_verification_id)
        if outcome and outcome.fix_verification_id
        else None
    )
    if fix is None and facts.get("controlled_retest_id"):
        fix = db.scalar(
            select(FixVerification).where(
                FixVerification.controlled_retest_id == facts["controlled_retest_id"],
                FixVerification.workflow_status == "current",
            )
        )
    anchor = outcome or fix
    current = root_cause_analysis_service.get_current_analysis(db, incident_id)
    result: dict[str, Any] = {
        "workflow_chain_status": "blocked",
        "blocked_reasons": [],
        "analysis": None,
        "review": None,
        "diagnosis": None,
        "action": None,
        "implementation": None,
        "patch": None,
        "test_execution": None,
        "controlled_retest": None,
        "fix_verification": fix,
        "outcome": outcome,
    }

    def fail_closed(reason: str) -> dict[str, Any]:
        result["blocked_reasons"].append(reason)
        for key in (
            "review", "diagnosis", "action", "implementation", "patch",
            "test_execution", "controlled_retest", "fix_verification", "outcome",
        ):
            result[key] = None
        return result
    if anchor is None:
        result["analysis"] = current
        if current is None:
            result["blocked_reasons"].append("No current root-cause analysis is available.")
            return result
        review = review_for_analysis(db, incident_id, current)
        result["review"] = review
        if review is not None and (
            review.incident_id == incident_id
            and review.root_cause_analysis_id == current.analysis_id
            and review.root_cause_analysis_version == current.analysis_version
            and review.evidence_snapshot_hash == current.evidence_snapshot_hash
            and str(review.decision).lower()
            == ReviewDecisionType.REJECTED_FALSE_POSITIVE.value
            and review.progression_valid
        ):
            result["workflow_chain_status"] = "current_false_positive"
            return result
        if review is not None and (
            review.incident_id != incident_id
            or review.root_cause_analysis_id != current.analysis_id
            or review.root_cause_analysis_version != current.analysis_version
            or review.evidence_snapshot_hash != current.evidence_snapshot_hash
            or str(review.decision).lower() != ReviewDecisionType.APPROVED.value
            or not review.progression_valid
        ):
            result["review"] = None
            result["blocked_reasons"].append(
                "The current review is not an approved progression-valid review for this analysis."
            )
            return result
        if review is not None:
            diagnosis = db.scalar(
                select(RemediationDiagnosis)
                .where(
                    RemediationDiagnosis.incident_id == incident_id,
                    RemediationDiagnosis.root_cause_analysis_id == current.analysis_id,
                    RemediationDiagnosis.root_cause_analysis_version == current.analysis_version,
                    RemediationDiagnosis.evidence_snapshot_hash == current.evidence_snapshot_hash,
                    RemediationDiagnosis.review_decision_id == review.id,
                    RemediationDiagnosis.derived_from_stale_analysis.is_(False),
                    RemediationDiagnosis.workflow_status == "current",
                )
                .order_by(
                    case((RemediationDiagnosis.status.in_(("accepted", "accepted_with_edits")), 0), else_=1),
                    RemediationDiagnosis.created_at.desc(), RemediationDiagnosis.id.desc(),
                )
                .limit(1)
            )
            action = db.scalar(
                select(RemediationAction).where(
                    RemediationAction.incident_id == incident_id,
                    RemediationAction.diagnosis_id == (diagnosis.diagnosis_id if diagnosis else None),
                    RemediationAction.review_decision_id == review.id,
                    RemediationAction.requires_revalidation.is_(False),
                    RemediationAction.workflow_status == "current",
                ).order_by(RemediationAction.created_at.desc(), RemediationAction.id.desc()).limit(1)
            ) if diagnosis else None
            if action is not None and (
                action.root_cause_analysis_id != current.analysis_id
                or action.review_decision_id != review.id
                or action.diagnosis_id != diagnosis.diagnosis_id
            ):
                action = None
            implementation = db.scalar(
                select(RemediationImplementationRecord).where(
                    RemediationImplementationRecord.incident_id == incident_id,
                    RemediationImplementationRecord.remediation_action_id == (action.remediation_action_id if action else None),
                    RemediationImplementationRecord.workflow_status == "current",
                ).order_by(RemediationImplementationRecord.created_at.desc(), RemediationImplementationRecord.id.desc()).limit(1)
            ) if action else None
            if implementation is not None and (
                implementation.root_cause_analysis_id != current.analysis_id
                or implementation.review_decision_id != review.id
                or implementation.diagnosis_id != diagnosis.diagnosis_id
                or implementation.remediation_action_id != action.remediation_action_id
            ):
                implementation = None
            test_exec = db.scalar(
                select(RemediationTestExecution).where(
                    RemediationTestExecution.incident_id == incident_id,
                    RemediationTestExecution.remediation_action_id == (action.remediation_action_id if action else None),
                    RemediationTestExecution.implementation_id == (implementation.implementation_id if implementation else None),
                    RemediationTestExecution.workflow_status == "current",
                ).order_by(RemediationTestExecution.created_at.desc(), RemediationTestExecution.id.desc()).limit(1)
            ) if implementation else None
            if test_exec is not None and (
                test_exec.remediation_action_id != action.remediation_action_id
                or test_exec.implementation_id != implementation.implementation_id
            ):
                test_exec = None
            retest = db.scalar(
                select(ControlledRetest).where(
                    ControlledRetest.incident_id == incident_id,
                    ControlledRetest.implementation_id == (implementation.implementation_id if implementation else None),
                    ControlledRetest.test_execution_id == (test_exec.execution_id if test_exec else None),
                    ControlledRetest.workflow_status == "current",
                ).order_by(ControlledRetest.created_at.desc(), ControlledRetest.id.desc()).limit(1)
            ) if test_exec else None
            if retest is not None and (
                retest.root_cause_analysis_id != current.analysis_id
                or retest.review_decision_id != review.id
                or retest.diagnosis_id != diagnosis.diagnosis_id
                or retest.remediation_action_id != action.remediation_action_id
                or retest.implementation_id != implementation.implementation_id
                or retest.test_execution_id != test_exec.execution_id
            ):
                retest = None
            patch = db.scalar(
                select(PatchProposal).where(
                    PatchProposal.incident_id == incident_id,
                    PatchProposal.remediation_action_id == (action.remediation_action_id if action else None),
                    PatchProposal.workflow_status == "current",
                ).order_by(PatchProposal.created_at.desc(), PatchProposal.id.desc()).limit(1)
            ) if action else None
            if patch is not None and (
                patch.root_cause_analysis_id != current.analysis_id
                or patch.remediation_action_id != action.remediation_action_id
            ):
                patch = None
            result.update(
                diagnosis=diagnosis,
                action=action,
                implementation=implementation,
                patch=patch,
                test_execution=test_exec,
                controlled_retest=retest,
            )
        result["workflow_chain_status"] = "current_incomplete"
        result["blocked_reasons"].append(
            "No current exact fix verification or verification outcome is available."
        )
        return result

    analysis = db.scalar(
        select(RootCauseAnalysis).where(
            RootCauseAnalysis.analysis_id == anchor.root_cause_analysis_id
        )
    )
    review = db.get(ReviewDecision, anchor.review_decision_id)
    diagnosis_id = (
        outcome.remediation_diagnosis_id if outcome else fix.remediation_diagnosis_id
    )
    action_id = outcome.remediation_action_id if outcome else fix.remediation_action_id
    implementation_id = outcome.implementation_id if outcome else fix.implementation_id
    test_id = outcome.test_execution_id if outcome else fix.test_execution_id
    retest_id = outcome.controlled_retest_id if outcome else fix.controlled_retest_id
    diagnosis = db.scalar(
        select(RemediationDiagnosis).where(RemediationDiagnosis.diagnosis_id == diagnosis_id)
    ) if diagnosis_id else None
    action = db.scalar(
        select(RemediationAction).where(RemediationAction.remediation_action_id == action_id)
    ) if action_id else None
    implementation = db.scalar(
        select(RemediationImplementationRecord).where(
            RemediationImplementationRecord.implementation_id == implementation_id
        )
    ) if implementation_id else None
    test_exec = db.scalar(
        select(RemediationTestExecution).where(RemediationTestExecution.execution_id == test_id)
    ) if test_id else None
    controlled_retest = db.scalar(
        select(ControlledRetest).where(ControlledRetest.controlled_retest_id == retest_id)
    ) if retest_id else None
    patch_id = outcome.patch_proposal_id if outcome else (
        implementation.patch_proposal_id if implementation else None
    )
    patch = db.scalar(
        select(PatchProposal).where(PatchProposal.patch_proposal_id == patch_id)
    ) if patch_id else None
    result.update(
        analysis=analysis,
        review=review,
        diagnosis=diagnosis,
        action=action,
        implementation=implementation,
        patch=patch,
        test_execution=test_exec,
        controlled_retest=controlled_retest,
    )

    rows = (analysis, review, diagnosis, action, implementation, test_exec, controlled_retest, fix, outcome)
    if any(row is None for row in rows):
        return fail_closed("The anchored verification chain is incomplete.")
    if (
        current is None
        or analysis.analysis_id != current.analysis_id
        or analysis.stale
        or not analysis.current
        or review.incident_id != incident_id
        or review.root_cause_analysis_id != analysis.analysis_id
        or review.root_cause_analysis_version != analysis.analysis_version
        or review.evidence_snapshot_hash != analysis.evidence_snapshot_hash
        or str(review.decision).lower() != ReviewDecisionType.APPROVED.value
        or not review.progression_valid
        or diagnosis.incident_id != incident_id
        or diagnosis.root_cause_analysis_id != analysis.analysis_id
        or diagnosis.review_decision_id != review.id
        or diagnosis.derived_from_stale_analysis
        or diagnosis.workflow_status != "current"
        or action.incident_id != incident_id
        or action.diagnosis_id != diagnosis.diagnosis_id
        or action.review_decision_id != review.id
        or action.requires_revalidation
        or action.workflow_status != "current"
        or implementation.incident_id != incident_id
        or implementation.root_cause_analysis_id != analysis.analysis_id
        or implementation.review_decision_id != review.id
        or implementation.diagnosis_id != diagnosis.diagnosis_id
        or implementation.remediation_action_id != action.remediation_action_id
        or implementation.workflow_status != "current"
        or test_exec.incident_id != incident_id
        or test_exec.remediation_action_id != action.remediation_action_id
        or test_exec.implementation_id != implementation.implementation_id
        or test_exec.workflow_status != "current"
        or controlled_retest.incident_id != incident_id
        or controlled_retest.root_cause_analysis_id != analysis.analysis_id
        or controlled_retest.review_decision_id != review.id
        or controlled_retest.diagnosis_id != diagnosis.diagnosis_id
        or controlled_retest.remediation_action_id != action.remediation_action_id
        or controlled_retest.implementation_id != implementation.implementation_id
        or controlled_retest.test_execution_id != test_exec.execution_id
        or controlled_retest.workflow_status != "current"
        or fix.incident_id != incident_id
        or fix.root_cause_analysis_id != analysis.analysis_id
        or fix.review_decision_id != review.id
        or fix.remediation_diagnosis_id != diagnosis.diagnosis_id
        or fix.remediation_action_id != action.remediation_action_id
        or fix.implementation_id != implementation.implementation_id
        or fix.test_execution_id != test_exec.execution_id
        or fix.controlled_retest_id != controlled_retest.controlled_retest_id
        or fix.workflow_status != "current"
    ):
        return fail_closed(
            "The anchored verification chain is stale, cross-branch, or does not belong to this incident."
        )
    if outcome and (
        outcome.incident_id != incident_id
        or outcome.workflow_status != "current"
        or outcome.fix_verification_id != fix.id
        or outcome.root_cause_analysis_id != analysis.analysis_id
        or outcome.review_decision_id != review.id
        or outcome.remediation_diagnosis_id != diagnosis.diagnosis_id
        or outcome.remediation_action_id != action.remediation_action_id
        or outcome.implementation_id != implementation.implementation_id
        or outcome.test_execution_id != test_exec.execution_id
        or outcome.controlled_retest_id != controlled_retest.controlled_retest_id
    ):
        return fail_closed("The verification outcome does not match its exact chain.")
    if patch and (
        patch.incident_id != incident_id
        or patch.remediation_action_id != action.remediation_action_id
        or patch.root_cause_analysis_id != analysis.analysis_id
        or patch.workflow_status != "current"
    ):
        return fail_closed("The patch reference does not match the exact chain.")
    result["workflow_chain_status"] = "current_complete"
    return result
