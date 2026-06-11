"""Persisted, human-controlled remediation actions."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.remediation_action import RemediationAction
from app.models.user import User
from app.services import audit_safety_service, audit_service, workflow_provenance_service
from app.services.audit_safety_service import AuditSafetyError
from app.services.workflow_provenance_service import WorkflowProvenanceError


READY_STATUSES = {"awaiting_retest", "completed"}


class RemediationActionError(Exception):
    pass


class IncidentNotFoundError(RemediationActionError):
    pass


class RemediationActionNotFoundError(RemediationActionError):
    pass


class RemediationNotAllowedError(RemediationActionError):
    pass


class UnsafeRemediationContentError(RemediationActionError):
    pass


def _safe_text(value: str | None) -> str | None:
    try:
        return audit_safety_service.prepare_review_comment(value)
    except AuditSafetyError as exc:
        raise UnsafeRemediationContentError(str(exc)) from exc


def _actor(db: Session, user_id: int | None) -> User | None:
    return db.get(User, user_id) if user_id else None


def create_remediation_action(
    db: Session,
    incident_id: str,
    *,
    created_by: int | None,
    action_type: str,
    action_description: str,
    affected_component: str,
    assigned_owner: str,
    status: str,
    priority: str,
    target_date,
    retest_required: bool,
    completion_notes: str | None,
) -> RemediationAction:
    try:
        permission = workflow_provenance_service.assert_current_governed_remediation_permission(
            db,
            incident_id,
            actor_id=created_by,
            require_active_human_actor=True,
        )
    except WorkflowProvenanceError as exc:
        if str(exc).startswith("Incident not found:"):
            raise IncidentNotFoundError(str(exc)) from exc
        raise RemediationNotAllowedError(str(exc)) from exc
    safe_description = _safe_text(action_description)
    safe_component = _safe_text(affected_component)
    safe_owner = _safe_text(assigned_owner)
    safe_notes = _safe_text(completion_notes)
    if not safe_description or not safe_component or not safe_owner:
        raise RemediationActionError("Description, component, and owner are required.")
    if status == "completed" and not safe_notes:
        raise RemediationActionError("Completion notes are required when status is completed.")

    action = RemediationAction(
        remediation_action_id=f"REM-{uuid4().hex[:12].upper()}",
        incident_id=incident_id,
        action_type=action_type,
        action_description=safe_description,
        affected_component=safe_component,
        assigned_owner=safe_owner,
        status=status,
        priority=priority,
        target_date=target_date,
        retest_required=retest_required,
        completion_notes=safe_notes,
        root_cause_analysis_id=permission.analysis_id,
        review_decision_id=permission.review.id,
        approved_by=created_by,
        approved_at=datetime.now(timezone.utc),
        workflow_status="current",
        created_by=created_by,
        completed_at=datetime.now(timezone.utc) if status == "completed" else None,
    )
    db.add(action)
    db.flush()
    actor = _actor(db, created_by)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_REMEDIATION_CREATED,
        actor_id=created_by,
        actor_email=actor.email if actor else None,
        actor_role=actor.role.value if actor else None,
        target_type="remediation_action",
        target_id=action.remediation_action_id,
        details={
            "incident_id": incident_id,
            "action_type": action_type,
            "status": status,
            "priority": priority,
            "human_saved": True,
            "production_change_performed_by_system": False,
        },
    )
    db.commit()
    db.refresh(action)
    return action


def list_remediation_actions(db: Session, incident_id: str) -> list[RemediationAction]:
    incident = db.scalar(select(Incident.id).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    return list(
        db.scalars(
            select(RemediationAction)
            .where(RemediationAction.incident_id == incident_id)
            .order_by(RemediationAction.created_at.desc(), RemediationAction.id.desc())
        ).all()
    )


def get_remediation_action(db: Session, remediation_action_id: str) -> RemediationAction:
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.remediation_action_id == remediation_action_id
        )
    )
    if action is None:
        raise RemediationActionNotFoundError(
            f"Remediation action not found: {remediation_action_id}"
        )
    return action


def update_remediation_action(
    db: Session,
    remediation_action_id: str,
    *,
    updated_by: int | None,
    changes: dict,
) -> RemediationAction:
    action = get_remediation_action(db, remediation_action_id)
    try:
        if action.root_cause_analysis_id and action.review_decision_id:
            permission = workflow_provenance_service.assert_current_governed_remediation_permission(
                db,
                action.incident_id,
                actor_id=updated_by,
                require_active_human_actor=True,
                root_cause_analysis_id=action.root_cause_analysis_id,
                review_decision_id=action.review_decision_id,
                diagnosis_id=action.diagnosis_id,
                remediation_action_id=action.remediation_action_id,
            )
        else:
            # A human update explicitly rebinds a legacy unreferenced action.
            permission = workflow_provenance_service.assert_current_governed_remediation_permission(
                db,
                action.incident_id,
                actor_id=updated_by,
                require_active_human_actor=True,
            )
            action.root_cause_analysis_id = permission.analysis_id
            action.review_decision_id = permission.review.id
            action.approved_by = updated_by
            action.approved_at = datetime.now(timezone.utc)
            action.requires_revalidation = False
            action.workflow_status = "current"
            action.invalidation_reason = None
    except WorkflowProvenanceError as exc:
        raise RemediationNotAllowedError(str(exc)) from exc
    previous_status = action.status
    safe_fields = {
        "action_description",
        "affected_component",
        "assigned_owner",
        "completion_notes",
    }
    for field, value in changes.items():
        if field in safe_fields:
            value = _safe_text(value)
        setattr(action, field, value)

    if not action.action_description or not action.affected_component or not action.assigned_owner:
        raise RemediationActionError("Description, component, and owner are required.")
    if action.status == "completed" and not action.completion_notes:
        raise RemediationActionError("Completion notes are required when status is completed.")
    if action.status == "completed" and previous_status != "completed":
        action.completed_at = datetime.now(timezone.utc)
    elif action.status != "completed":
        action.completed_at = None
    action.updated_at = datetime.now(timezone.utc)

    actor = _actor(db, updated_by)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_REMEDIATION_UPDATED,
        actor_id=updated_by,
        actor_email=actor.email if actor else None,
        actor_role=actor.role.value if actor else None,
        target_type="remediation_action",
        target_id=action.remediation_action_id,
        details={
            "incident_id": action.incident_id,
            "changed_fields": sorted(changes),
            "previous_status": previous_status,
            "new_status": action.status,
            "human_saved": True,
        },
    )
    db.commit()
    db.refresh(action)
    return action


def remediation_is_complete(action: RemediationAction) -> bool:
    return bool(
        action.action_description
        and action.affected_component
        and action.assigned_owner
        and action.status in READY_STATUSES
    )
