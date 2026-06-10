"""Exact-chain controlled fix verification."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import FixVerification
from app.models.enums import IncidentStatus, VerificationStatus
from app.models.incident import Incident
from app.models.user import User
from app.models.workflow_verification import VerificationOutcome
from app.services import (
    audit_safety_service,
    audit_service,
    fix_verification_gate_service,
    fix_verification_policy_service,
    verification_outcome_service,
)
from app.services.fix_verification_gate_service import FixVerificationNotAllowedError

ALL_CHECKS = [
    "current_governed_chain",
    "completed_implementation",
    "applicable_passed_safe_test",
    "controlled_retest_present",
    "controlled_retest_dimensions_match",
    "canonical_exposure_engine_result",
]

SAFE_SUMMARIES = {
    VerificationStatus.PASSED: (
        "Fix verification passed based on the matching controlled retest. Human review remains required."
    ),
    VerificationStatus.FAILED: (
        "Fix verification failed because the canonical exposure engine detected the original sensitive exposure after the change."
    ),
    VerificationStatus.INCONCLUSIVE: (
        "Fix verification is inconclusive because the controlled retest does not match the original exposure dimensions."
    ),
}


class FixVerificationServiceError(Exception):
    pass


class IncidentNotFoundError(FixVerificationServiceError):
    pass


# Compatibility aliases retained for router imports.
class RetestEvidenceNotFoundError(FixVerificationServiceError):
    pass


class RetestEvidenceNotLinkedError(FixVerificationServiceError):
    pass


@dataclass
class VerifyFixResult:
    verification: FixVerification
    incident_status: IncidentStatus
    human_review_required: bool
    safe_summary: str
    verification_outcome_id: str | None
    eligible_for_learning: bool


def verification_status_for_retest(
    *, dimensions_match: bool, raw_exposure_after_change: bool | None
) -> VerificationStatus:
    if not dimensions_match or raw_exposure_after_change is None:
        return VerificationStatus.INCONCLUSIVE
    return (
        VerificationStatus.FAILED
        if raw_exposure_after_change
        else VerificationStatus.PASSED
    )


def verify_fix(
    db: Session,
    incident_id: str,
    *,
    controlled_retest_id: str | None = None,
    requested_by: int | None = None,
    retest_evidence_ids: list[str] | None = None,
) -> VerifyFixResult:
    del retest_evidence_ids  # legacy request field cannot bypass controlled retest provenance
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    context = fix_verification_gate_service.assert_fix_verification_allowed(
        db,
        incident_id,
        actor_id=requested_by,
        controlled_retest_id=controlled_retest_id,
    )
    retest = context.controlled_retest
    existing = db.scalar(
        select(FixVerification).where(
            FixVerification.controlled_retest_id == retest.controlled_retest_id
        )
    )
    if existing is not None:
        outcome = db.scalar(
            select(VerificationOutcome).where(
                VerificationOutcome.fix_verification_id == existing.id
            )
        )
        return VerifyFixResult(
            verification=existing,
            incident_status=incident.status,
            human_review_required=True,
            safe_summary=SAFE_SUMMARIES[existing.verification_status],
            verification_outcome_id=(
                outcome.verification_outcome_id if outcome is not None else None
            ),
            eligible_for_learning=bool(outcome and outcome.eligible_for_learning),
        )

    status = verification_status_for_retest(
        dimensions_match=retest.dimensions_match,
        raw_exposure_after_change=retest.raw_exposure_after_change,
    )

    failed = []
    passed = ALL_CHECKS[:4]
    if retest.dimensions_match:
        passed.append("controlled_retest_dimensions_match")
    else:
        failed.append("controlled_retest_dimensions_match")
    if retest.raw_exposure_after_change is None:
        failed.append("canonical_exposure_engine_result")
    else:
        passed.append("canonical_exposure_engine_result")

    record = FixVerification(
        incident_id=incident_id,
        root_cause_analysis_id=context.permission.analysis_id,
        review_decision_id=context.permission.review.id,
        remediation_diagnosis_id=context.permission.diagnosis.diagnosis_id,
        remediation_action_id=context.action.remediation_action_id,
        implementation_id=context.implementation.implementation_id,
        test_execution_id=context.test_execution.execution_id,
        controlled_retest_id=retest.controlled_retest_id,
        verification_status=status,
        checks_run=ALL_CHECKS,
        passed_checks=passed,
        failed_checks=failed,
        evidence_used=[retest.original_finding_id, retest.controlled_retest_id],
    )
    db.add(record)
    db.flush()
    fix_verification_policy_service.apply_verification_status_to_incident(incident, status)

    diagnosis = context.permission.diagnosis
    primary = diagnosis.primary_remediation or {}
    original = {
        "finding_id": retest.original_finding_id,
        "service": diagnosis.affected_service or incident.affected_service,
        "endpoint": diagnosis.affected_endpoint or incident.affected_endpoint,
        "exposure_location": primary.get("exposure_location"),
        "sensitive_type": retest.sensitive_type,
        "component": diagnosis.affected_component,
    }
    retest_result = {
        "finding_id": retest.retest_finding_id,
        "service": retest.service_name,
        "endpoint": retest.endpoint,
        "exposure_location": retest.exposure_location,
        "sensitive_type": retest.sensitive_type,
        "component": retest.component,
        "raw_exposure_after_change": retest.raw_exposure_after_change,
    }
    test_result = {
        "execution_id": context.test_execution.execution_id,
        "passed": context.test_execution.status == "passed",
        "raw_value_leakage_result": int(
            context.test_execution.raw_leakage_count or 0
        ),
    }
    actor = db.get(User, requested_by) if requested_by is not None else None
    outcome = verification_outcome_service.build_verification_outcome(
        db,
        incident_id=incident_id,
        diagnosis=diagnosis,
        verification=record,
        patch_id=context.implementation.patch_proposal_id,
        test_result=test_result,
        retest_result=retest_result,
        remediation_action_id=context.action.remediation_action_id,
        test_execution_id=context.test_execution.execution_id,
        implementation_id=context.implementation.implementation_id,
        controlled_retest_id=retest.controlled_retest_id,
        implementation_mode=context.implementation.implementation_mode,
        original_exposure=original,
        actor_id=requested_by,
        actor_email=actor.email if actor else None,
        actor_role=actor.role.value if actor else None,
        commit=False,
    )
    safe_summary = SAFE_SUMMARIES[status]
    audit_service.log_action(
        db,
        action=audit_service.ACTION_FIX_VERIFICATION_COMPLETED,
        actor_id=requested_by,
        target_type="incident",
        target_id=incident_id,
        details=audit_safety_service.validate_and_sanitize_audit_details(
            {
                "fix_verification_id": record.id,
                "verification_outcome_id": outcome["verification_outcome_id"],
                "controlled_retest_id": retest.controlled_retest_id,
                "verification_status": status.value,
                "safe_summary": safe_summary,
            }
        ),
    )
    db.commit()
    db.refresh(record)
    db.refresh(incident)
    if (
        status == VerificationStatus.FAILED
        and context.implementation.implementation_mode == "controlled_patch"
    ):
        from app.services import controlled_rollback_service

        controlled_rollback_service.maybe_auto_rollback_controlled_patch(
            db,
            implementation=context.implementation,
            trigger=controlled_rollback_service.TRIGGER_FIX_VERIFICATION_FAILED,
            trigger_reference=str(record.id),
            actor_id=requested_by,
        )
        db.refresh(incident)
    return VerifyFixResult(
        verification=record,
        incident_status=incident.status,
        human_review_required=True,
        safe_summary=safe_summary,
        verification_outcome_id=outcome["verification_outcome_id"],
        eligible_for_learning=bool(outcome["eligible_for_learning"]),
    )


def list_fix_verifications(db: Session, incident_id: str) -> list[FixVerification]:
    if db.scalar(select(Incident.id).where(Incident.incident_id == incident_id)) is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    return list(
        db.scalars(
            select(FixVerification)
            .where(FixVerification.incident_id == incident_id)
            .order_by(FixVerification.timestamp.desc(), FixVerification.id.desc())
        ).all()
    )
