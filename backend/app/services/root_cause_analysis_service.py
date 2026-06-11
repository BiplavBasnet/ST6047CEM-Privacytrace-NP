"""First-class RootCauseAnalysis identity — versioned, stale-aware parent."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.remediation_action import RemediationAction
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.review_decision import ReviewDecision
from app.models.root_cause_analysis import RootCauseAnalysis
from app.models.fix_verification import FixVerification
from app.models.verified_remediation_learning import PatchProposal, VerifiedRemediationCase
from app.models.workflow_verification import (
    ControlledRetest,
    RemediationImplementationRecord,
    RemediationTestExecution,
    VerificationOutcome,
)


def get_current_analysis(db: Session, incident_id: str) -> RootCauseAnalysis | None:
    return db.scalar(
        select(RootCauseAnalysis)
        .where(
            RootCauseAnalysis.incident_id == incident_id,
            RootCauseAnalysis.current.is_(True),
        )
        .order_by(RootCauseAnalysis.analysis_version.desc(), RootCauseAnalysis.id.desc())
        .limit(1)
    )


def get_latest_analysis(db: Session, incident_id: str) -> RootCauseAnalysis | None:
    return db.scalar(
        select(RootCauseAnalysis)
        .where(RootCauseAnalysis.incident_id == incident_id)
        .order_by(RootCauseAnalysis.analysis_version.desc(), RootCauseAnalysis.id.desc())
        .limit(1)
    )


def ensure_current_analysis(db: Session, incident_id: str) -> RootCauseAnalysis | None:
    """Return current analysis, backfilling from RootCauseScore rows when needed.

    Legacy seeds/tests may create score rows without a RootCauseAnalysis parent.
    Progression still requires a first-class analysis identity.

    If an analysis row already exists but is stale/non-current, do **not** recreate
    it (unique analysis_id) — return None so callers treat progression as blocked.
    """
    current = get_current_analysis(db, incident_id)
    if current is not None:
        return current

    from app.models.root_cause_score import RootCauseScore

    scores = list(
        db.scalars(
            select(RootCauseScore)
            .where(RootCauseScore.incident_id == incident_id)
            .order_by(RootCauseScore.analysis_version.desc(), RootCauseScore.id.desc())
        ).all()
    )
    if not scores:
        return None

    sample = next((s for s in scores if not s.stale), scores[0])
    analysis_id = sample.analysis_id or f"RCA-LEGACY-{incident_id[-12:]}"

    existing = db.scalar(
        select(RootCauseAnalysis).where(RootCauseAnalysis.analysis_id == analysis_id).limit(1)
    )
    if existing is not None:
        # Already have a parent row — if it is not current, progression stays blocked.
        return existing if existing.current and not existing.stale else None

    cohort = [s for s in scores if (s.analysis_id or analysis_id) == analysis_id] or [sample]
    version = max((s.analysis_version or 1) for s in cohort)
    snap = next(
        (s.evidence_snapshot_hash for s in cohort if s.evidence_snapshot_hash),
        f"legacy-score-{analysis_id}",
    )
    for s in cohort:
        if not s.analysis_id:
            s.analysis_id = analysis_id
            s.evidence_snapshot_hash = s.evidence_snapshot_hash or snap
            db.add(s)
    return create_analysis_record(
        db,
        analysis_id=analysis_id,
        incident_id=incident_id,
        analysis_version=version,
        evidence_snapshot_hash=snap,
        rules_version=sample.rules_version,
        analysed_at=sample.analysed_at,
    )


def create_analysis_record(
    db: Session,
    *,
    analysis_id: str,
    incident_id: str,
    analysis_version: int,
    evidence_snapshot_hash: str,
    rules_version: str | None = None,
    taxonomy_version: str | None = None,
    exposure_policy_version: str | None = None,
    analysed_at: datetime | None = None,
    evidence_revision: int = 1,
) -> RootCauseAnalysis:
    """Persist a new current analysis; mark any previous current rows superseded/stale."""
    previous = list(
        db.scalars(
            select(RootCauseAnalysis).where(
                RootCauseAnalysis.incident_id == incident_id,
                RootCauseAnalysis.current.is_(True),
            )
        ).all()
    )
    for row in previous:
        row.current = False
        row.stale = True
        row.stale_reason = row.stale_reason or "Superseded by a newer root-cause analysis."
        row.superseded_by_analysis_id = analysis_id
        db.add(row)
        invalidate_reviews_for_progression(
            db,
            analysis_id=row.analysis_id,
            reason="Root-cause analysis superseded by a newer analysis.",
        )
        invalidate_downstream_for_stale_analysis(db, analysis_id=row.analysis_id)

    record = RootCauseAnalysis(
        analysis_id=analysis_id,
        incident_id=incident_id,
        analysis_version=analysis_version,
        rules_version=rules_version,
        taxonomy_version=taxonomy_version,
        exposure_policy_version=exposure_policy_version,
        evidence_snapshot_hash=evidence_snapshot_hash,
        evidence_revision=evidence_revision,
        analysed_at=analysed_at or datetime.now(UTC),
        stale=False,
        stale_reason=None,
        superseded_by_analysis_id=None,
        current=True,
    )
    db.add(record)
    db.flush()
    return record


def invalidate_reviews_for_progression(
    db: Session,
    *,
    analysis_id: str,
    reason: str,
) -> int:
    reviews = list(
        db.scalars(
            select(ReviewDecision).where(
                ReviewDecision.root_cause_analysis_id == analysis_id,
                ReviewDecision.progression_valid.is_(True),
            )
        ).all()
    )
    for review in reviews:
        review.progression_valid = False
        review.progression_invalid_reason = reason
        db.add(review)
    return len(reviews)


def invalidate_downstream_for_stale_analysis(
    db: Session,
    *,
    analysis_id: str,
    reason: str = "Root-cause analysis is stale; current-chain revalidation is required.",
) -> dict[str, int]:
    diagnoses = list(
        db.scalars(
            select(RemediationDiagnosis).where(
                RemediationDiagnosis.root_cause_analysis_id == analysis_id
            )
        ).all()
    )
    for diag in diagnoses:
        diag.derived_from_stale_analysis = True
        diag.workflow_status = "stale"
        db.add(diag)

    actions = list(
        db.scalars(
            select(RemediationAction).where(RemediationAction.root_cause_analysis_id == analysis_id)
        ).all()
    )
    for action in actions:
        action.requires_revalidation = True
        action.workflow_status = "stale"
        action.invalidation_reason = reason
        db.add(action)

    patches = list(
        db.scalars(
            select(PatchProposal).where(PatchProposal.root_cause_analysis_id == analysis_id)
        ).all()
    )
    action_ids = {row.remediation_action_id for row in actions}
    implementations = list(
        db.scalars(
            select(RemediationImplementationRecord).where(
                RemediationImplementationRecord.remediation_action_id.in_(action_ids)
            )
        ).all()
    ) if action_ids else []
    for implementation in implementations:
        implementation.workflow_status = "stale"
        implementation.invalidation_reason = reason
        db.add(implementation)
    implementation_ids = {row.implementation_id for row in implementations}
    for patch in patches:
        patch.workflow_status = "stale"
        patch.invalidation_reason = reason
        db.add(patch)

    tests = list(
        db.scalars(
            select(RemediationTestExecution).where(
                RemediationTestExecution.remediation_action_id.in_(action_ids)
            )
        ).all()
    ) if action_ids else []
    for test in tests:
        test.workflow_status = "stale"
        test.invalidation_reason = reason
        db.add(test)

    retests = list(
        db.scalars(
            select(ControlledRetest).where(
                ControlledRetest.implementation_id.in_(implementation_ids)
            )
        ).all()
    ) if implementation_ids else []
    for retest in retests:
        retest.workflow_status = "stale"
        retest.invalidation_reason = reason
        db.add(retest)
    retest_ids = {row.controlled_retest_id for row in retests}

    verifications = list(
        db.scalars(
            select(FixVerification).where(
                FixVerification.controlled_retest_id.in_(retest_ids)
            )
        ).all()
    ) if retest_ids else []
    for verification in verifications:
        verification.workflow_status = "stale"
        verification.invalidation_reason = reason
        db.add(verification)

    outcomes = list(
        db.scalars(
            select(VerificationOutcome).where(
                VerificationOutcome.root_cause_analysis_id == analysis_id
            )
        ).all()
    )
    outcome_ids = {row.verification_outcome_id for row in outcomes}
    for outcome in outcomes:
        outcome.workflow_status = "stale"
        outcome.invalidation_reason = reason
        outcome.eligible_for_learning = False
        outcome.eligibility_reason = reason
        db.add(outcome)

    cases = list(
        db.scalars(
            select(VerifiedRemediationCase).where(
                VerifiedRemediationCase.verification_outcome_id.in_(outcome_ids)
            )
        ).all()
    ) if outcome_ids else []
    for case in cases:
        case.workflow_status = "stale"
        case.invalidation_reason = reason
        case.eligible_for_learning = False
        case.eligibility_reason = reason
        db.add(case)
    return {
        "diagnoses": len(diagnoses),
        "actions": len(actions),
        "implementations": len(implementations),
        "patches": len(patches),
        "tests": len(tests),
        "controlled_retests": len(retests),
        "fix_verifications": len(verifications),
        "outcomes": len(outcomes),
        "learning_cases": len(cases),
    }


def mark_analysis_stale(db: Session, analysis_id: str, reason: str) -> RootCauseAnalysis | None:
    analysis = db.scalar(
        select(RootCauseAnalysis).where(RootCauseAnalysis.analysis_id == analysis_id)
    )
    if analysis is None:
        return None
    analysis.stale = True
    analysis.stale_reason = reason
    analysis.current = False
    db.add(analysis)
    invalidate_reviews_for_progression(db, analysis_id=analysis_id, reason=reason)
    invalidate_downstream_for_stale_analysis(db, analysis_id=analysis_id, reason=reason)
    return analysis


def ensure_seed_analysis_for_incident(
    db: Session,
    incident_id: str,
    *,
    analysis_id: str | None = None,
    evidence_snapshot_hash: str = "seed-snapshot",
    analysis_version: int = 1,
) -> RootCauseAnalysis:
    """Create a current analysis when tests/fixtures only seeded score rows."""
    existing = get_current_analysis(db, incident_id)
    if existing:
        return existing
    aid = analysis_id or f"RCA-SEED-{incident_id[-12:]}"
    return create_analysis_record(
        db,
        analysis_id=aid,
        incident_id=incident_id,
        analysis_version=analysis_version,
        evidence_snapshot_hash=evidence_snapshot_hash,
        analysed_at=datetime.now(UTC),
    )
