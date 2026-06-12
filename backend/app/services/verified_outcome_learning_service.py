"""Verified-outcome learning — PostgreSQL-backed playbooks (survives restart)."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from sqlalchemy import or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.fix_verification import FixVerification
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.verified_remediation_learning import RemediationPlaybook, VerifiedRemediationCase
from app.models.workflow_verification import VerificationOutcome
from app.services import audit_service

# Categorical weights for deterministic ranking (no embeddings / raw values).
_RANK_WEIGHTS = {
    "sensitive_type": 3,
    "exposure_location": 3,
    "root_cause_category": 4,
    "affected_component": 2,
    "remediation_type": 3,
    "implementation_mode": 1,
}


def remediation_fingerprint(
    *,
    remediation_type: str | None,
    root_cause_category: str | None,
    sensitive_type: str | None,
    exposure_location: str | None,
    affected_component: str | None,
    implementation_mode: str | None = None,
) -> str:
    """Structured fingerprint only — never raw sensitive payload values."""
    parts = [
        str(remediation_type or "").strip().casefold(),
        str(root_cause_category or "").strip().casefold(),
        str(sensitive_type or "").strip().casefold(),
        str(exposure_location or "").strip().casefold(),
        str(affected_component or "").strip().casefold(),
        str(implementation_mode or "").strip().casefold(),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"rfp:{digest[:32]}"


def eligibility_for_learning(
    *,
    diagnosis: RemediationDiagnosis | None,
    verification: FixVerification | None,
) -> dict[str, Any]:
    if diagnosis is None or diagnosis.status not in {"accepted", "accepted_with_edits"}:
        return {
            "eligible_for_learning": False,
            "eligibility_reason": "Remediation diagnosis was not human-accepted.",
        }
    if verification is None:
        return {
            "eligible_for_learning": False,
            "eligibility_reason": "No fix verification record is available.",
        }
    status_raw = getattr(verification, "verification_status", None)
    status = str(getattr(status_raw, "value", status_raw) or "").lower()
    if status != "passed":
        return {
            "eligible_for_learning": False,
            "eligibility_reason": (
                "Only verification passed based on available controlled retest evidence "
                "may influence future ranking."
            ),
        }
    return {
        "eligible_for_learning": True,
        "eligibility_reason": (
            "Recommendation ranking may be informed by previously human-approved and "
            "verified remediation outcomes."
        ),
    }


def _get_or_create_playbook(
    db: Session,
    *,
    remediation_type: str,
    root_cause_category: str | None,
) -> RemediationPlaybook:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": f"remediation-playbook:{remediation_type}"},
        )
    existing = db.scalar(
        select(RemediationPlaybook).where(
            RemediationPlaybook.remediation_type == remediation_type,
            RemediationPlaybook.active.is_(True),
        )
    )
    if existing:
        return existing
    row = RemediationPlaybook(
        playbook_id=f"PB-{uuid.uuid4().hex[:10].upper()}",
        root_cause_category=root_cause_category or "unknown",
        exposure_locations=[],
        sensitive_types=[],
        component_category=None,
        remediation_pattern=remediation_type,
        remediation_type=remediation_type,
        test_pattern="allowlisted synthetic regression",
        retest_pattern="same service/endpoint/exposure_location/sensitive_type",
        rollback_guidance="Restore sandbox original snapshot.",
        verified_success_count=0,
        verified_failure_count=0,
        inconclusive_count=0,
        version="1",
        active=True,
    )
    db.add(row)
    db.flush()
    return row


def _bump_playbook_counter(
    db: Session,
    *,
    remediation_type: str | None,
    root_cause_category: str | None,
    result: str,
) -> dict[str, Any]:
    if not remediation_type:
        return {}
    playbook = _get_or_create_playbook(
        db,
        remediation_type=str(remediation_type),
        root_cause_category=str(root_cause_category) if root_cause_category else None,
    )
    values: dict[str, Any]
    if result == "passed":
        values = {"verified_success_count": RemediationPlaybook.verified_success_count + 1}
    elif result in {"failed", "rolled_back"}:
        values = {"verified_failure_count": RemediationPlaybook.verified_failure_count + 1}
    else:
        values = {"inconclusive_count": RemediationPlaybook.inconclusive_count + 1}
    db.execute(update(RemediationPlaybook).where(RemediationPlaybook.id == playbook.id).values(**values))
    db.flush()
    db.refresh(playbook)
    return {
        "playbook_id": playbook.playbook_id,
        "verified_success_count": playbook.verified_success_count,
        "verified_failure_count": playbook.verified_failure_count,
        "inconclusive_count": playbook.inconclusive_count,
    }


def record_verified_outcome(
    db: Session,
    *,
    incident_id: str,
    diagnosis_id: str | None,
    verification_id: str | None,
    remediation_action_id: str | None = None,
    patch_proposal_id: str | None = None,
    tests_passed: bool | None = None,
    verification_outcome_id: str | None = None,
    sensitive_type: str | None = None,
    exposure_location: str | None = None,
    root_cause_category: str | None = None,
    actor_id: int | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    commit: bool = True,
) -> dict[str, Any]:
    if verification_outcome_id:
        existing_case = db.scalar(
            select(VerifiedRemediationCase).where(
                VerifiedRemediationCase.verification_outcome_id == verification_outcome_id
            )
        )
        if existing_case is not None:
            return {
                "verified_case_id": existing_case.verified_case_id,
                "incident_id": existing_case.incident_id,
                "sensitive_type": existing_case.sensitive_type,
                "exposure_location": existing_case.exposure_location,
                "root_cause_category": existing_case.root_cause_category,
                "remediation_type": existing_case.remediation_type,
                "playbook_stats": {},
                "persisted": True,
                "eligible_for_learning": existing_case.eligible_for_learning,
                "eligibility_reason": existing_case.eligibility_reason,
                "idempotent_reuse": True,
            }
    diagnosis = None
    if diagnosis_id:
        diagnosis = db.scalar(
            select(RemediationDiagnosis).where(RemediationDiagnosis.diagnosis_id == diagnosis_id)
        )
    verification = None
    if verification_id:
        try:
            verification = db.get(FixVerification, int(verification_id))
        except (TypeError, ValueError):
            verification = None

    eligibility = eligibility_for_learning(diagnosis=diagnosis, verification=verification)
    outcome = (
        db.scalar(
            select(VerificationOutcome).where(
                VerificationOutcome.verification_outcome_id == verification_outcome_id
            )
        )
        if verification_outcome_id
        else None
    )
    if (
        outcome is None
        or outcome.workflow_status != "current"
        or not outcome.eligible_for_learning
        or outcome.verification_result != "passed"
        or not outcome.implementation_id
        or not outcome.controlled_retest_id
        or not outcome.test_execution_id
    ):
        eligibility = {
            "eligible_for_learning": False,
            "eligibility_reason": (
                "Learning requires the current complete passed exact-chain verification outcome."
            ),
        }
    remediation_type = None
    primary = diagnosis.primary_remediation if diagnosis and isinstance(diagnosis.primary_remediation, dict) else {}

    # Canonical taxonomy only — never map problem_statement into sensitive_type.
    remediation_type = primary.get("remediation_type")
    resolved_sensitive = sensitive_type or primary.get("sensitive_type")
    resolved_exposure = exposure_location or primary.get("exposure_location")
    resolved_category = (
        root_cause_category
        or primary.get("root_cause_category")
        or primary.get("cause_name")
    )
    # Guard: reject free-text problem statements mistakenly passed as taxonomy.
    if resolved_sensitive and diagnosis and resolved_sensitive == diagnosis.problem_statement:
        resolved_sensitive = primary.get("sensitive_type")
    if resolved_category and diagnosis and resolved_category == diagnosis.problem_statement:
        resolved_category = primary.get("root_cause_category")

    status_raw = getattr(verification, "verification_status", None) if verification else None
    verification_result = str(getattr(status_raw, "value", status_raw) or "inconclusive")
    if outcome is not None and outcome.verification_result:
        verification_result = str(outcome.verification_result)

    fp = remediation_fingerprint(
        remediation_type=str(remediation_type) if remediation_type else None,
        root_cause_category=str(resolved_category) if resolved_category else None,
        sensitive_type=str(resolved_sensitive) if resolved_sensitive else None,
        exposure_location=str(resolved_exposure) if resolved_exposure else None,
        affected_component=diagnosis.affected_component if diagnosis else None,
        implementation_mode=(
            outcome.implementation_mode if outcome and outcome.implementation_mode else "controlled_patch"
        ),
    )

    case = VerifiedRemediationCase(
        verified_case_id=f"VRC-{uuid.uuid4().hex[:12].upper()}",
        incident_id=incident_id,
        diagnosis_id=diagnosis_id,
        remediation_action_id=remediation_action_id,
        patch_proposal_id=patch_proposal_id,
        sensitive_type=str(resolved_sensitive) if resolved_sensitive else None,
        exposure_location=str(resolved_exposure) if resolved_exposure else None,
        root_cause_category=str(resolved_category) if resolved_category else None,
        affected_component=diagnosis.affected_component if diagnosis else None,
        remediation_type=str(remediation_type) if remediation_type else None,
        remediation_fingerprint=fp,
        approved_remediation_summary=(
            primary.get("recommended_change") if primary else None
        ),
        implementation_mode="controlled_local_test_workspace",
        tests_passed=tests_passed,
        verification_result=verification_result,
        verified_by=actor_email,
        eligible_for_learning=bool(eligibility["eligible_for_learning"]),
        eligibility_reason=eligibility["eligibility_reason"],
        policy_version="playbook-v1",
        verification_outcome_id=verification_outcome_id,
        semantics_version="v2",
        limitations=list(diagnosis.limitations) if diagnosis else [],
    )
    try:
        with db.begin_nested():
            db.add(case)
            db.flush()
    except IntegrityError:
        existing_case = db.scalar(
            select(VerifiedRemediationCase).where(
                VerifiedRemediationCase.verification_outcome_id
                == verification_outcome_id
            )
        )
        if existing_case is None:
            raise
        return {
            "verified_case_id": existing_case.verified_case_id,
            "incident_id": existing_case.incident_id,
            "sensitive_type": existing_case.sensitive_type,
            "exposure_location": existing_case.exposure_location,
            "root_cause_category": existing_case.root_cause_category,
            "remediation_type": existing_case.remediation_type,
            "playbook_stats": {},
            "persisted": True,
            "eligible_for_learning": existing_case.eligible_for_learning,
            "eligibility_reason": existing_case.eligibility_reason,
            "idempotent_reuse": True,
        }

    playbook_stats: dict[str, Any] = {}
    if remediation_type:
        if eligibility["eligible_for_learning"] and verification_result == "passed":
            playbook_stats = _bump_playbook_counter(
                db,
                remediation_type=str(remediation_type),
                root_cause_category=str(resolved_category) if resolved_category else None,
                result="passed",
            )
        elif verification_result in {"failed", "rolled_back"}:
            playbook_stats = _bump_playbook_counter(
                db,
                remediation_type=str(remediation_type),
                root_cause_category=str(resolved_category) if resolved_category else None,
                result=verification_result,
            )
        elif verification_result == "inconclusive":
            playbook_stats = _bump_playbook_counter(
                db,
                remediation_type=str(remediation_type),
                root_cause_category=str(resolved_category) if resolved_category else None,
                result="inconclusive",
            )

    audit_service.log_action(
        db,
        action="verified_outcome_learning_eligibility",
        target_type="verified_remediation_case",
        target_id=case.verified_case_id,
        details={
            "incident_id": incident_id,
            "diagnosis_id": diagnosis_id,
            "verification_id": verification_id,
            "sensitive_type": resolved_sensitive,
            "exposure_location": resolved_exposure,
            "root_cause_category": resolved_category,
            **eligibility,
            "remediation_type": remediation_type,
            "policy_note": (
                "Verified outcome-informed remediation ranking. "
                "Recommendation ranking is informed by previously human-approved and "
                "verified remediation outcomes."
            ),
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    if commit:
        db.commit()
        db.refresh(case)
    else:
        db.flush()
    return {
        "verified_case_id": case.verified_case_id,
        "incident_id": incident_id,
        "sensitive_type": resolved_sensitive,
        "exposure_location": resolved_exposure,
        "root_cause_category": resolved_category,
        "remediation_type": remediation_type,
        "playbook_stats": playbook_stats,
        "persisted": True,
        **eligibility,
    }


def playbook_ranking_hint(db: Session, remediation_type: str) -> dict[str, Any]:
    playbook = db.scalar(
        select(RemediationPlaybook).where(
            RemediationPlaybook.remediation_type == remediation_type,
            RemediationPlaybook.active.is_(True),
        )
    )
    if not playbook:
        return {
            "remediation_type": remediation_type,
            "verified_successful_outcomes": 0,
            "verified_failed_outcomes": 0,
            "inconclusive_outcomes": 0,
            "policy_version": "playbook-v1",
            "persisted": True,
            "note": (
                "Verified outcome-informed remediation ranking. "
                "No verified cases recorded yet for this remediation type."
            ),
        }
    return {
        "remediation_type": remediation_type,
        "playbook_id": playbook.playbook_id,
        "verified_successful_outcomes": playbook.verified_success_count,
        "verified_failed_outcomes": playbook.verified_failure_count,
        "inconclusive_outcomes": playbook.inconclusive_count,
        "policy_version": playbook.version,
        "persisted": True,
        "note": (
            "Verified outcome-informed remediation ranking. "
            "Recommendation ranking is informed by previously human-approved and "
            "verified remediation outcomes."
        ),
    }


def ranking_influence_for_similar(
    db: Session,
    *,
    root_cause_category: str | None = None,
    remediation_type: str | None = None,
    sensitive_type: str | None = None,
    exposure_location: str | None = None,
    affected_component: str | None = None,
    implementation_mode: str | None = None,
) -> dict[str, Any]:
    """Rank prior verified successes; penalise identical failed fingerprints."""
    context = {
        "sensitive_type": sensitive_type,
        "exposure_location": exposure_location,
        "root_cause_category": root_cause_category,
        "affected_component": affected_component,
        "remediation_type": remediation_type,
        "implementation_mode": implementation_mode,
    }
    fp = remediation_fingerprint(**context)

    successes = list(
        db.scalars(
            select(VerifiedRemediationCase).where(
                VerifiedRemediationCase.eligible_for_learning.is_(True),
                VerifiedRemediationCase.verification_result == "passed",
                VerifiedRemediationCase.workflow_status == "current",
            ).limit(50)
        ).all()
    )
    ranked: list[dict[str, Any]] = []
    for case in successes:
        score = 0
        why: list[str] = []
        for field, weight in _RANK_WEIGHTS.items():
            want = context.get(field)
            have = getattr(case, field, None)
            if want and have and str(want).casefold() == str(have).casefold():
                score += weight
                why.append(f"matched {field}")
        if score <= 0 and not (remediation_type or root_cause_category):
            continue
        if remediation_type and case.remediation_type == remediation_type and score == 0:
            score = 1
            why.append("matched remediation_type")
        if root_cause_category and case.root_cause_category == root_cause_category and "matched root_cause_category" not in why:
            score += _RANK_WEIGHTS["root_cause_category"]
            why.append("matched root_cause_category")
        ranked.append(
            {
                "verified_case_id": case.verified_case_id,
                "remediation_type": case.remediation_type,
                "score": score,
                "why_selected": why,
                "eligible_for_learning": True,
            }
        )
    ranked.sort(key=lambda item: (-int(item["score"]), str(item["verified_case_id"])))

    failed_filters = [VerifiedRemediationCase.remediation_fingerprint == fp]
    if remediation_type:
        failed_filters.append(VerifiedRemediationCase.remediation_type == remediation_type)
    failed_same = list(
        db.scalars(
            select(VerifiedRemediationCase).where(
                VerifiedRemediationCase.verification_result.in_(["failed", "rolled_back"]),
                or_(*failed_filters),
            ).limit(20)
        ).all()
    )
    failed_count = len(failed_same)
    max_attempts = int(get_settings().remediation_max_failed_attempts)
    block_identical = failed_count >= max_attempts
    preferred = ranked[0]["remediation_type"] if ranked else remediation_type
    return {
        "comparable_verified_cases": len(ranked),
        "preferred_remediation_type": preferred,
        "case_ids": [c["verified_case_id"] for c in ranked[:20]],
        "ranked_cases": ranked[:10],
        "negative_fingerprint_hits": failed_count,
        "remediation_fingerprint": fp,
        "block_identical_auto_retry": block_identical,
        "human_review_required": True,
        "note": (
            "Verified outcome-informed remediation ranking. "
            "Previously verified remediation matched this incident where score > 0. "
            "Human approval remains required."
        ),
    }


def fingerprint_attempt_gate(
    db: Session,
    *,
    remediation_type: str | None,
    root_cause_category: str | None,
    sensitive_type: str | None,
    exposure_location: str | None,
    affected_component: str | None,
) -> dict[str, Any]:
    influence = ranking_influence_for_similar(
        db,
        remediation_type=remediation_type,
        root_cause_category=root_cause_category,
        sensitive_type=sensitive_type,
        exposure_location=exposure_location,
        affected_component=affected_component,
        implementation_mode="controlled_patch",
    )
    return {
        "remediation_fingerprint": influence["remediation_fingerprint"],
        "block_identical_auto_retry": influence["block_identical_auto_retry"],
        "negative_fingerprint_hits": influence["negative_fingerprint_hits"],
        "more_evidence_required": bool(influence["block_identical_auto_retry"]),
        "human_review_required": True,
    }
