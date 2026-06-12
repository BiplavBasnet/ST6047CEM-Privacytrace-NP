"""Persist VerificationOutcome from diagnosis + retest + fix verification.

Does not invent success. Wording follows controlled-retest evidence rules.
Canonical learning fields come from taxonomy/playbook — never problem_statement.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import VerificationStatus
from app.models.fix_verification import FixVerification
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.workflow_verification import VerificationOutcome
from app.services import audit_service, verified_outcome_learning_service

_WORDING = {
    VerificationStatus.PASSED: (
        "Verification passed based on available controlled retest evidence."
    ),
    VerificationStatus.FAILED: (
        "Verification failed because the same sensitive-data exposure was observed after remediation."
    ),
    VerificationStatus.INCONCLUSIVE: (
        "Verification is inconclusive because the available retest evidence does not "
        "sufficiently reproduce the original exposure condition."
    ),
}


def _match_bool(left: Any, right: Any) -> bool | None:
    if left is None or right is None:
        return None
    return str(left).strip().lower() == str(right).strip().lower()


def _canonical_fields(diagnosis: RemediationDiagnosis | None) -> dict[str, str | None]:
    primary = diagnosis.primary_remediation if diagnosis and isinstance(diagnosis.primary_remediation, dict) else {}
    return {
        "sensitive_type": primary.get("sensitive_type"),
        "exposure_location": primary.get("exposure_location"),
        "root_cause_category": primary.get("root_cause_category")
        or primary.get("cause_name"),
        "remediation_type": primary.get("remediation_type"),
    }


def build_verification_outcome(
    db: Session,
    *,
    incident_id: str,
    diagnosis: RemediationDiagnosis | None,
    verification: FixVerification | None,
    patch_id: str | None = None,
    test_result: dict[str, Any] | None = None,
    retest_result: dict[str, Any] | None = None,
    remediation_action_id: str | None = None,
    test_execution_id: str | None = None,
    implementation_id: str | None = None,
    controlled_retest_id: str | None = None,
    implementation_mode: str | None = None,
    original_exposure: dict[str, Any] | None = None,
    verified_by: str | None = None,
    actor_id: int | None = None,
    actor_email: str | None = None,
    actor_role: str | None = None,
    commit: bool = True,
) -> dict[str, Any]:
    if verification is not None:
        existing = db.scalar(
            select(VerificationOutcome).where(
                VerificationOutcome.fix_verification_id == verification.id
            )
        )
        if existing is not None:
            return {
                "verification_outcome_id": existing.verification_outcome_id,
                "incident_id": existing.incident_id,
                "verification_id": existing.fix_verification_id,
                "verification_result": existing.verification_result,
                "eligible_for_learning": existing.eligible_for_learning,
                "eligibility_reason": existing.eligibility_reason,
                "idempotent_reuse": True,
            }
    if verification is None:
        status = VerificationStatus.INCONCLUSIVE
        result_text = _WORDING[status]
    else:
        status = verification.verification_status
        result_text = _WORDING.get(status, _WORDING[VerificationStatus.INCONCLUSIVE])

    original = original_exposure or {}
    retest = retest_result or {}
    tests = test_result or {}

    same_service = _match_bool(original.get("service"), retest.get("service") or (diagnosis.affected_service if diagnosis else None))
    same_endpoint = _match_bool(original.get("endpoint"), retest.get("endpoint") or (diagnosis.affected_endpoint if diagnosis else None))
    same_exposure = _match_bool(original.get("exposure_location"), retest.get("exposure_location"))
    same_sensitive = _match_bool(original.get("sensitive_type"), retest.get("sensitive_type"))
    same_component = _match_bool(original.get("component"), retest.get("component") or (diagnosis.affected_component if diagnosis else None))
    tests_passed = bool(tests.get("passed")) if "passed" in tests else None
    raw_after = None
    if "raw_exposure_after_change" in retest:
        value = retest.get("raw_exposure_after_change")
        raw_after = bool(value) if value is not None else None
    elif "raw_value_leakage_result" in tests:
        raw_after = bool(tests.get("raw_value_leakage_result"))
    complete_passed_chain = bool(
        diagnosis
        and diagnosis.status in {"accepted", "accepted_with_edits"}
        and verification
        and status == VerificationStatus.PASSED
        and implementation_id
        and controlled_retest_id
        and test_execution_id
        and tests_passed is True
        and raw_after is False
        and all(
            match is True
            for match in (
                same_service,
                same_endpoint,
                same_exposure,
                same_sensitive,
                same_component,
            )
        )
    )
    eligibility = {
        "eligible_for_learning": complete_passed_chain,
        "eligibility_reason": (
            "Complete current exact chain passed controlled verification."
            if complete_passed_chain
            else "Learning requires a complete current passed exact controlled-retest chain."
        ),
    }

    outcome_id = f"VO-{uuid.uuid4().hex[:12].upper()}"
    row = VerificationOutcome(
        verification_outcome_id=outcome_id,
        incident_id=incident_id,
        root_cause_analysis_id=diagnosis.root_cause_analysis_id if diagnosis else None,
        review_decision_id=diagnosis.review_decision_id if diagnosis else None,
        remediation_diagnosis_id=diagnosis.diagnosis_id if diagnosis else None,
        remediation_action_id=remediation_action_id,
        patch_proposal_id=patch_id,
        test_execution_id=test_execution_id or tests.get("execution_id"),
        implementation_id=implementation_id,
        controlled_retest_id=controlled_retest_id,
        original_exposure_finding_id=original.get("finding_id"),
        retest_finding_id=retest.get("finding_id"),
        fix_verification_id=verification.id if verification else None,
        implementation_mode=implementation_mode,
        same_service_match=same_service,
        same_endpoint_match=same_endpoint,
        same_exposure_location_match=same_exposure,
        same_sensitive_type_match=same_sensitive,
        same_component_match=same_component,
        tests_passed=tests_passed,
        raw_exposure_after_change=raw_after,
        verification_result=status.value if hasattr(status, "value") else str(status),
        limitations=list(diagnosis.limitations) if diagnosis else [],
        verified_by=verified_by or actor_email,
        verified_at=datetime.now(UTC),
        eligible_for_learning=bool(eligibility["eligible_for_learning"]),
        eligibility_reason=eligibility["eligibility_reason"],
    )
    db.add(row)
    db.flush()

    canonical = _canonical_fields(diagnosis)
    learning: dict[str, Any] = {}
    if diagnosis is not None:
        learning = verified_outcome_learning_service.record_verified_outcome(
            db,
            incident_id=incident_id,
            diagnosis_id=diagnosis.diagnosis_id,
            verification_id=str(verification.id) if verification else None,
            remediation_action_id=remediation_action_id,
            patch_proposal_id=patch_id,
            tests_passed=tests_passed,
            verification_outcome_id=outcome_id,
            sensitive_type=canonical.get("sensitive_type"),
            exposure_location=canonical.get("exposure_location"),
            root_cause_category=canonical.get("root_cause_category"),
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            commit=False,
        )

    audit_service.log_action(
        db,
        action="verified_outcome_created",
        target_type="incident",
        target_id=incident_id,
        details={
            "verification_outcome_id": outcome_id,
            "verification_result": row.verification_result,
            "eligible_for_learning": row.eligible_for_learning,
            "remediation_diagnosis_id": row.remediation_diagnosis_id,
            "verification_wording": result_text,
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    if commit:
        db.commit()
        db.refresh(row)
    return {
        "verification_outcome_id": row.verification_outcome_id,
        "incident_id": incident_id,
        "root_cause_analysis_id": row.root_cause_analysis_id,
        "remediation_diagnosis_id": row.remediation_diagnosis_id,
        "human_approved_remediation": bool(
            diagnosis and diagnosis.status in {"accepted", "accepted_with_edits"}
        ),
        "patch_id": patch_id,
        "test_result": tests,
        "retest_result": retest,
        "verification_id": verification.id if verification else None,
        "verification_result": row.verification_result,
        "verification_wording": result_text,
        "same_service_match": same_service,
        "same_endpoint_match": same_endpoint,
        "same_exposure_location_match": same_exposure,
        "same_sensitive_type_match": same_sensitive,
        "same_component_match": same_component,
        "tests_passed": tests_passed,
        "raw_exposure_after_change": raw_after,
        "limitations": row.limitations,
        "verified_by": row.verified_by,
        "verified_at": row.verified_at.isoformat() if row.verified_at else None,
        "learning": learning,
        **eligibility,
    }
