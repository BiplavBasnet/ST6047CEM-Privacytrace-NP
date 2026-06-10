"""Canonical exact-chain precondition for fix verification."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import IncidentStatus
from app.models.remediation_action import RemediationAction
from app.models.workflow_verification import (
    ControlledRetest,
    RemediationImplementationRecord,
    RemediationTestExecution,
)
from app.services import workflow_provenance_service
from app.services.workflow_provenance_service import WorkflowProvenanceError


class FixVerificationNotAllowedError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class FixVerificationContext:
    permission: workflow_provenance_service.ValidReviewContext
    action: RemediationAction
    implementation: RemediationImplementationRecord
    test_execution: RemediationTestExecution
    controlled_retest: ControlledRetest


def assert_fix_verification_allowed(
    db: Session,
    incident_id: str,
    *,
    actor_id: int | None = None,
    require_actor: bool = True,
    controlled_retest_id: str | None = None,
) -> FixVerificationContext:
    provenance = workflow_provenance_service.get_workflow_provenance_facts(db, incident_id)
    action_id = provenance.get("remediation_action_id")
    if not action_id:
        raise FixVerificationNotAllowedError(
            "Fix verification requires the current approved remediation action."
        )
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.remediation_action_id == action_id
        )
    )
    if (
        action is None
        or action.status not in {"awaiting_retest", "completed"}
        or action.approved_by is None
        or action.requires_revalidation
        or action.workflow_status != "current"
    ):
        raise FixVerificationNotAllowedError(
            "Fix verification requires an approved current action awaiting retest or completed."
        )
    try:
        permission = workflow_provenance_service.assert_current_governed_remediation_permission(
            db,
            incident_id,
            actor_id=actor_id,
            require_active_human_actor=require_actor,
            remediation_action_id=action.remediation_action_id,
        )
    except WorkflowProvenanceError as exc:
        raise FixVerificationNotAllowedError(str(exc)) from exc
    if permission.diagnosis is None:
        raise FixVerificationNotAllowedError(
            "Fix verification requires the current accepted remediation diagnosis."
        )
    if permission.incident.status == IncidentStatus.CLOSED:
        raise FixVerificationNotAllowedError(
            "Fix verification is not allowed for closed incidents."
        )

    implementation = db.scalar(
        select(RemediationImplementationRecord)
        .where(
            RemediationImplementationRecord.incident_id == incident_id,
            RemediationImplementationRecord.remediation_action_id
            == action.remediation_action_id,
            RemediationImplementationRecord.root_cause_analysis_id
            == permission.analysis_id,
            RemediationImplementationRecord.review_decision_id == permission.review.id,
            RemediationImplementationRecord.diagnosis_id
            == permission.diagnosis.diagnosis_id,
            RemediationImplementationRecord.status == "completed",
            RemediationImplementationRecord.workflow_status == "current",
        )
        .order_by(RemediationImplementationRecord.created_at.desc())
        .limit(1)
    )
    if implementation is None:
        raise FixVerificationNotAllowedError(
            "Fix verification requires a completed current implementation record."
        )
    test = db.scalar(
        select(RemediationTestExecution)
        .where(
            RemediationTestExecution.incident_id == incident_id,
            RemediationTestExecution.remediation_action_id == action.remediation_action_id,
            RemediationTestExecution.implementation_id == implementation.implementation_id,
            RemediationTestExecution.status == "passed",
            RemediationTestExecution.safety_status == "ok",
            RemediationTestExecution.raw_leakage_count == 0,
            RemediationTestExecution.workflow_status == "current",
        )
        .order_by(RemediationTestExecution.completed_at.desc(), RemediationTestExecution.id.desc())
        .limit(1)
    )
    if test is None:
        raise FixVerificationNotAllowedError(
            "Fix verification requires the applicable passed safe persisted test execution."
        )
    retest_query = select(ControlledRetest).where(
        ControlledRetest.incident_id == incident_id,
        ControlledRetest.remediation_action_id == action.remediation_action_id,
        ControlledRetest.implementation_id == implementation.implementation_id,
        ControlledRetest.test_execution_id == test.execution_id,
        ControlledRetest.root_cause_analysis_id == permission.analysis_id,
        ControlledRetest.review_decision_id == permission.review.id,
        ControlledRetest.diagnosis_id == permission.diagnosis.diagnosis_id,
        ControlledRetest.safety_status == "ok",
        ControlledRetest.dimensions_match.is_(True),
        ControlledRetest.workflow_status == "current",
    )
    if controlled_retest_id:
        retest_query = retest_query.where(
            ControlledRetest.controlled_retest_id == controlled_retest_id
        )
    retest = db.scalar(
        retest_query.order_by(ControlledRetest.completed_at.desc()).limit(1)
    )
    required_contract = {
        "service_name", "endpoint", "sensitive_type", "exposure_location", "component"
    }
    if (
        retest is None
        or set(retest.required_dimensions or []) != required_contract
        or retest.missing_dimensions
    ):
        raise FixVerificationNotAllowedError(
            "Fix verification requires a controlled retest linked to the exact current chain."
        )
    return FixVerificationContext(permission, action, implementation, test, retest)


def can_start_fix_verification(db: Session, incident_id: str) -> bool:
    try:
        assert_fix_verification_allowed(db, incident_id, require_actor=False)
    except FixVerificationNotAllowedError:
        return False
    return True
