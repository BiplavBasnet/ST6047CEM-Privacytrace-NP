"""Persist implementation and controlled-retest records for the current chain."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection import Detection
from app.models.remediation_action import RemediationAction
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.verified_remediation_learning import PatchProposal
from app.models.workflow_verification import (
    ControlledRetest,
    RemediationImplementationRecord,
    RemediationTestExecution,
)
from app.services import (
    audit_safety_service,
    audit_service,
    sensitive_exposure_engine,
    workflow_provenance_service,
)
from app.services.workflow_provenance_service import WorkflowProvenanceError

IMPLEMENTATION_MODES = {
    "controlled_patch",
    "manual",
    "external_configuration_change",
}


class RemediationLifecycleError(ValueError):
    pass


def _permission_for_action(
    db: Session,
    action: RemediationAction,
    *,
    actor_id: int | None,
) -> workflow_provenance_service.ValidReviewContext:
    try:
        return workflow_provenance_service.assert_current_governed_remediation_permission(
            db,
            action.incident_id,
            actor_id=actor_id,
            require_active_human_actor=True,
            remediation_action_id=action.remediation_action_id,
        )
    except WorkflowProvenanceError as exc:
        raise RemediationLifecycleError(str(exc)) from exc


def get_implementation(
    db: Session, implementation_id: str
) -> RemediationImplementationRecord:
    row = db.scalar(
        select(RemediationImplementationRecord).where(
            RemediationImplementationRecord.implementation_id == implementation_id
        )
    )
    if row is None:
        raise RemediationLifecycleError(f"Implementation not found: {implementation_id}")
    return row


def record_implementation(
    db: Session,
    *,
    remediation_action_id: str,
    implementation_mode: str,
    implementation_summary: str,
    actor_id: int | None,
    expected_incident_id: str | None = None,
    patch_proposal_id: str | None = None,
    change_reference_safe: str | None = None,
    change_hash: str | None = None,
    commit: bool = True,
) -> RemediationImplementationRecord:
    if implementation_mode not in IMPLEMENTATION_MODES:
        raise RemediationLifecycleError("Unsupported implementation mode.")
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.remediation_action_id == remediation_action_id
        ).with_for_update()
    )
    if action is None:
        raise RemediationLifecycleError(f"Remediation action not found: {remediation_action_id}")
    if expected_incident_id is not None and action.incident_id != expected_incident_id:
        raise RemediationLifecycleError(
            "Implementation action does not belong to the requested incident."
        )
    permission = _permission_for_action(db, action, actor_id=actor_id)
    if permission.diagnosis is None or action.approved_by is None:
        raise RemediationLifecycleError(
            "Implementation requires a human-approved current diagnosis action."
        )

    patch = None
    if implementation_mode == "controlled_patch":
        patch = db.scalar(
            select(PatchProposal).where(
                PatchProposal.patch_proposal_id == patch_proposal_id,
                PatchProposal.remediation_action_id == remediation_action_id,
            )
        )
        if patch is None or patch.status != "applied_to_sandbox":
            raise RemediationLifecycleError(
                "Controlled-patch implementation requires its applied sandbox patch."
            )
        change_reference_safe = patch.repository_reference_safe
        change_hash = patch.post_apply_workspace_hash
    elif patch_proposal_id is not None:
        raise RemediationLifecycleError(
            "Manual/configuration implementation cannot reference a patch proposal."
        )

    safe_summary = audit_safety_service.prepare_review_comment(implementation_summary)
    safe_reference = audit_safety_service.prepare_review_comment(change_reference_safe)
    if not safe_summary:
        raise RemediationLifecycleError("Implementation summary is required.")
    identity = "\x1f".join((patch_proposal_id or "", change_hash or "", safe_reference or "", safe_summary))
    idempotency_key = (
        f"implementation:{remediation_action_id}:{implementation_mode}:"
        f"{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"
    )
    existing = db.scalar(
        select(RemediationImplementationRecord).where(
            RemediationImplementationRecord.idempotency_key == idempotency_key
        )
    )
    if existing is not None:
        return existing

    row = RemediationImplementationRecord(
        implementation_id=f"RIM-{uuid.uuid4().hex[:12].upper()}",
        incident_id=action.incident_id,
        root_cause_analysis_id=permission.analysis_id,
        review_decision_id=permission.review.id,
        diagnosis_id=permission.diagnosis.diagnosis_id,
        remediation_action_id=action.remediation_action_id,
        patch_proposal_id=patch.patch_proposal_id if patch else None,
        implementation_mode=implementation_mode,
        change_reference_safe=safe_reference,
        change_hash=change_hash,
        implementation_summary=safe_summary,
        status="completed",
        idempotency_key=idempotency_key,
        implemented_by_user_id=actor_id,
        implemented_at=datetime.now(UTC),
        workflow_status="current",
    )
    db.add(row)
    if action.status == "not_started":
        action.status = "awaiting_retest"
        db.add(action)
    db.flush()
    audit_service.log_action(
        db,
        action="remediation_implementation_recorded",
        actor_id=actor_id,
        target_type="remediation_implementation",
        target_id=row.implementation_id,
        details={
            "incident_id": row.incident_id,
            "remediation_action_id": remediation_action_id,
            "implementation_mode": implementation_mode,
            "patch_proposal_id": row.patch_proposal_id,
        },
    )
    if commit:
        db.commit()
        db.refresh(row)
    return row


def record_controlled_retest(
    db: Session,
    *,
    implementation_id: str,
    test_execution_id: str,
    original_finding_id: str,
    source_type: str,
    synthetic_output: str,
    service_name: str | None,
    endpoint: str | None,
    exposure_location: str | None,
    component: str | None,
    environment: str | None,
    actor_id: int | None,
    expected_incident_id: str | None = None,
) -> ControlledRetest:
    implementation = get_implementation(db, implementation_id)
    if (
        expected_incident_id is not None
        and implementation.incident_id != expected_incident_id
    ):
        raise RemediationLifecycleError(
            "Controlled retest does not belong to the requested incident."
        )
    if implementation.workflow_status != "current" or implementation.status != "completed":
        raise RemediationLifecycleError("Implementation is not current and completed.")
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.remediation_action_id
            == implementation.remediation_action_id
        )
    )
    assert action is not None  # protected by FK/current-chain creation
    permission = _permission_for_action(db, action, actor_id=actor_id)
    if permission.diagnosis is None:
        raise RemediationLifecycleError("Controlled retest requires a current diagnosis.")
    if (
        implementation.incident_id != action.incident_id
        or implementation.root_cause_analysis_id != permission.analysis_id
        or implementation.review_decision_id != permission.review.id
        or implementation.diagnosis_id != permission.diagnosis.diagnosis_id
    ):
        raise RemediationLifecycleError("Implementation does not belong to the current chain.")

    test = db.scalar(
        select(RemediationTestExecution).where(
            RemediationTestExecution.execution_id == test_execution_id
        )
    )
    if (
        test is None
        or test.incident_id != action.incident_id
        or test.remediation_action_id != action.remediation_action_id
        or test.implementation_id != implementation_id
        or test.workflow_status != "current"
        or test.status != "passed"
        or test.safety_status != "ok"
        or int(test.raw_leakage_count or 0) != 0
    ):
        raise RemediationLifecycleError(
            "Controlled retest requires the applicable passed safe persisted test execution."
        )

    original = db.scalar(
        select(Detection).where(
            Detection.detection_id == original_finding_id,
            Detection.incident_id == action.incident_id,
        )
    )
    if original is None:
        raise RemediationLifecycleError(
            "Original finding must be a detection linked to the same incident."
        )

    primary = permission.diagnosis.primary_remediation or {}
    expected_service = permission.diagnosis.affected_service or permission.incident.affected_service
    expected_endpoint = permission.diagnosis.affected_endpoint or permission.incident.affected_endpoint
    expected_exposure = primary.get("exposure_location")
    expected_component = permission.diagnosis.affected_component
    dimension_values = {
        "service_name": (service_name, expected_service),
        "endpoint": (endpoint, expected_endpoint),
        "exposure_location": (exposure_location, expected_exposure),
        "component": (component, expected_component),
        "sensitive_type": (original.sensitive_type, original.sensitive_type),
    }
    required_dimensions = list(dimension_values)
    missing_dimensions = [
        name for name, (actual, expected) in dimension_values.items()
        if not str(actual or "").strip() or not str(expected or "").strip()
    ]
    dimensions_match = not missing_dimensions and all(
        str(actual).strip().casefold() == str(expected).strip().casefold()
        for actual, expected in dimension_values.values()
    )
    findings = sensitive_exposure_engine.analyse(
        source_type=source_type,
        text=synthetic_output,
        service=service_name,
        endpoint=endpoint,
        environment=environment,
        event_time=datetime.now(UTC),
        context_metadata={"exposure_location": exposure_location},
    )
    matching = [
        finding
        for finding in findings
        if finding.get("sensitive_type") == original.sensitive_type
        and (
            expected_exposure is None
            or finding.get("exposure_location") == expected_exposure
        )
    ]
    raw_after = any(
        finding.get("exposure_decision") == "unsafe_exposure" for finding in matching
    )
    now = datetime.now(UTC)
    existing = db.scalar(
        select(ControlledRetest).where(
            ControlledRetest.implementation_id == implementation_id,
            ControlledRetest.test_execution_id == test_execution_id,
        )
    )
    if existing is not None:
        return existing
    row = ControlledRetest(
        controlled_retest_id=f"CRT-{uuid.uuid4().hex[:12].upper()}",
        incident_id=action.incident_id,
        root_cause_analysis_id=permission.analysis_id,
        review_decision_id=permission.review.id,
        diagnosis_id=permission.diagnosis.diagnosis_id,
        remediation_action_id=action.remediation_action_id,
        implementation_id=implementation_id,
        test_execution_id=test_execution_id,
        original_finding_id=original_finding_id,
        retest_finding_id=matching[0]["finding_id"] if matching else None,
        service_name=service_name,
        endpoint=endpoint,
        exposure_location=exposure_location,
        sensitive_type=original.sensitive_type,
        component=component,
        environment=environment,
        dimensions_match=dimensions_match,
        required_dimensions=required_dimensions,
        missing_dimensions=missing_dimensions,
        raw_exposure_after_change=raw_after if dimensions_match else None,
        finding_count=len(findings),
        safe_findings=findings,
        safety_status="ok",
        status="completed" if dimensions_match else "inconclusive",
        started_at=now,
        completed_at=now,
        created_by_user_id=actor_id,
        workflow_status="current",
    )
    db.add(row)
    db.flush()
    audit_service.log_action(
        db,
        action="controlled_retest_recorded",
        actor_id=actor_id,
        target_type="controlled_retest",
        target_id=row.controlled_retest_id,
        details={
            "incident_id": row.incident_id,
            "implementation_id": implementation_id,
            "test_execution_id": test_execution_id,
            "dimensions_match": dimensions_match,
            "raw_exposure_after_change": row.raw_exposure_after_change,
            "finding_count": row.finding_count,
        },
    )
    # Failed comparable retest (unsafe exposure still present) → controlled rollback.
    if dimensions_match and raw_after and implementation.implementation_mode == "controlled_patch":
        from app.services import controlled_rollback_service

        row.status = "failed"
        db.add(row)
        db.flush()
        controlled_rollback_service.maybe_auto_rollback_controlled_patch(
            db,
            implementation=implementation,
            trigger=controlled_rollback_service.TRIGGER_RETEST_FAILED,
            trigger_reference=row.controlled_retest_id,
            actor_id=actor_id,
        )
    db.commit()
    db.refresh(row)
    return row


def current_lifecycle_records(db: Session, incident_id: str) -> dict[str, object | None]:
    chain = workflow_provenance_service.get_exact_report_chain(db, incident_id)
    outcome = chain.get("outcome")
    from app.models.incident import Incident
    from app.models.rollback_execution import RollbackExecution
    from app.models.verified_remediation_learning import VerifiedRemediationCase

    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    learning = db.scalar(select(VerifiedRemediationCase).where(
        VerifiedRemediationCase.verification_outcome_id == (outcome.verification_outcome_id if outcome else None),
        VerifiedRemediationCase.workflow_status == "current",
    ).limit(1)) if outcome else None
    implementation = chain.get("implementation")
    test = chain.get("test_execution")
    retest = chain.get("controlled_retest")
    rollback = db.scalar(
        select(RollbackExecution)
        .where(RollbackExecution.incident_id == incident_id)
        .order_by(RollbackExecution.id.desc())
        .limit(1)
    )
    status_value = ""
    if incident is not None:
        status_value = str(getattr(incident.status, "value", incident.status) or "")
    phase = derive_lifecycle_phase(
        incident_status=status_value,
        implementation=implementation,
        test=test,
        retest=retest,
        outcome=outcome,
        rollback=rollback,
        learning_eligible=bool(learning and learning.eligible_for_learning),
    )
    return {
        "implementation": implementation,
        "test_execution": test,
        "controlled_retest": retest,
        "fix_verification_id": chain["fix_verification"].id if chain.get("fix_verification") else None,
        "verification_outcome_id": outcome.verification_outcome_id if outcome else None,
        "verification_result": outcome.verification_result if outcome else None,
        "verified_case_id": learning.verified_case_id if learning else None,
        "learning_eligible": learning.eligible_for_learning if learning else False,
        "workflow_chain_status": chain["workflow_chain_status"],
        "lifecycle_phase": phase,
        "rollback_execution_id": rollback.rollback_execution_id if rollback else None,
        "rollback_status": rollback.status if rollback else None,
        "rollback_verification": rollback.verification_result if rollback else None,
        "rollback_verified": rollback.rollback_verified if rollback else None,
    }


def derive_lifecycle_phase(
    *,
    incident_status: str,
    implementation,
    test,
    retest,
    outcome,
    rollback,
    learning_eligible: bool,
) -> str:
    status = str(incident_status or "").lower()
    if status in {"false_positive"}:
        return "FALSE_POSITIVE"
    if status in {"closed"}:
        return "CLOSED"
    if status in {"fixed"} or (outcome and getattr(outcome, "verification_result", None) == "passed" and learning_eligible):
        return "RESOLVED"
    if outcome and getattr(outcome, "verification_result", None) == "inconclusive":
        return "VERIFYING"
    if rollback and rollback.status == "succeeded":
        return "REMEDIATING"
    if test and getattr(test, "status", None) == "failed":
        return "REMEDIATING"
    if retest and getattr(retest, "status", None) == "failed":
        return "REMEDIATING"
    if outcome and getattr(outcome, "verification_result", None) == "failed":
        return "REMEDIATING"
    if implementation and getattr(implementation, "status", None) == "rolled_back":
        return "REMEDIATING"
    if retest or (test and getattr(test, "status", None) == "passed"):
        return "VERIFYING"
    if implementation:
        return "REMEDIATING"
    if status in {"under_review", "confirmed_incident", "needs_more_evidence"}:
        return "INVESTIGATING"
    return "OPEN"
