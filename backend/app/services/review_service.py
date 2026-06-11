"""Human review decisions and incident status updates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.enums import IncidentStatus
from app.models.incident import Incident
from app.models.review_decision import ReviewDecision
from app.models.review_draft import ReviewDraft
from app.models.user import User
from app.services import audit_service, audit_safety_service, review_policy_service
from app.services import root_cause_analysis_service
from app.services.audit_safety_service import AuditSafetyError
from app.services.review_policy_service import InvalidReviewDecisionError

# Backward-compatible aliases for tests and routers.
InvalidDecisionError = InvalidReviewDecisionError
parse_decision = review_policy_service.parse_review_decision
map_review_decision_to_status = review_policy_service.map_review_decision_to_status


@dataclass
class SubmitReviewResult:
    review: ReviewDecision
    incident_status: IncidentStatus
    audit_log: AuditLog


class ReviewServiceError(Exception):
    """Base error for review workflow."""


class IncidentNotFoundError(ReviewServiceError):
    pass


class AnalyseRequiredError(ReviewServiceError):
    pass


class ReviewerNotFoundError(ReviewServiceError):
    pass


class UnsafeReviewCommentError(ReviewServiceError):
    pass


class ReviewReasonRequiredError(ReviewServiceError):
    pass


def _prepare_safe_items(values: list[str] | None) -> list[str]:
    safe: list[str] = []
    for value in values or []:
        prepared = audit_safety_service.prepare_review_comment(str(value))
        if prepared:
            safe.append(prepared)
    return safe


def submit_review(
    db: Session,
    incident_id: str,
    *,
    decision: str,
    reviewer_id: int | None = None,
    comment: str | None = None,
    reason: str | None = None,
    evidence_checklist: list[str] | None = None,
    evidence_relied_on: list[str] | None = None,
    evidence_limitations: str | None = None,
    missing_evidence_acknowledged: bool = False,
    limitations_acknowledged: bool = False,
) -> SubmitReviewResult:
    stmt = select(Incident).where(Incident.incident_id == incident_id)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        stmt = stmt.with_for_update()
    incident = db.scalar(stmt)
    if not incident:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")

    current_analysis = root_cause_analysis_service.ensure_current_analysis(db, incident_id)
    if current_analysis is None:
        raise AnalyseRequiredError(
            "Incident must be analysed before human review; "
            "a current root-cause analysis is required — run POST /incidents/analyse first."
        )

    try:
        decision_enum = review_policy_service.parse_review_decision(decision)
    except InvalidReviewDecisionError:
        raise

    if reviewer_id is not None:
        reviewer = db.scalar(select(User).where(User.id == reviewer_id))
        if not reviewer:
            raise ReviewerNotFoundError(f"Reviewer user not found: {reviewer_id}")

    if not (reason or comment or "").strip():
        raise ReviewReasonRequiredError("A decision reason is required.")

    try:
        safe_reason = audit_safety_service.prepare_review_comment(reason or comment)
        safe_comment = audit_safety_service.prepare_review_comment(comment)
        safe_checklist = _prepare_safe_items(evidence_checklist)
        safe_evidence = _prepare_safe_items(evidence_relied_on)
        safe_limitations = audit_safety_service.prepare_review_comment(evidence_limitations)
    except AuditSafetyError as exc:
        raise UnsafeReviewCommentError(str(exc)) from exc

    previous_status = incident.status.value
    new_status = review_policy_service.map_review_decision_to_status(decision_enum)
    incident.status = new_status

    submitted_at = datetime.now(timezone.utc)
    review = ReviewDecision(
        incident_id=incident_id,
        reviewer_id=reviewer_id,
        decision=decision_enum.value,
        comment=safe_comment,
        reason=safe_reason,
        evidence_checklist=safe_checklist,
        evidence_relied_on=safe_evidence,
        evidence_limitations=safe_limitations,
        missing_evidence_acknowledged=missing_evidence_acknowledged,
        root_cause_analysis_id=current_analysis.analysis_id,
        root_cause_analysis_version=current_analysis.analysis_version,
        evidence_snapshot_hash=current_analysis.evidence_snapshot_hash,
        limitations_acknowledged=limitations_acknowledged,
        progression_valid=True,
        progression_invalid_reason=None,
        submitted_at=submitted_at,
        timestamp=submitted_at,
    )
    db.add(review)
    db.flush()

    audit_details = audit_safety_service.validate_and_sanitize_audit_details(
        {
            "incident_id": incident_id,
            "review_decision_id": review.id,
            "decision": decision_enum.value,
            "previous_incident_status": previous_status,
            "new_incident_status": new_status.value,
            "reviewer_id": reviewer_id,
            "root_cause_analysis_id": current_analysis.analysis_id,
            "root_cause_analysis_version": current_analysis.analysis_version,
            "evidence_snapshot_hash": current_analysis.evidence_snapshot_hash,
            "reason_summary": (
                (safe_reason[:240] + "...")
                if safe_reason and len(safe_reason) > 240
                else safe_reason
            ),
            "human_review_required": decision_enum.value != "approved",
            "confidence_level": "human_review_recorded",
        }
    )

    reviewer = db.get(User, reviewer_id) if reviewer_id else None
    audit_entry = audit_service.log_action(
        db,
        action=audit_service.ACTION_REVIEW_SUBMITTED,
        actor_id=reviewer_id,
        actor_email=reviewer.email if reviewer else None,
        actor_role=reviewer.role.value if reviewer else None,
        target_type="incident",
        target_id=incident_id,
        details=audit_details,
    )
    draft = db.scalar(select(ReviewDraft).where(ReviewDraft.incident_id == incident_id))
    if draft is not None:
        db.delete(draft)
    db.commit()
    db.refresh(review)
    db.refresh(incident)

    return SubmitReviewResult(
        review=review,
        incident_status=incident.status,
        audit_log=audit_entry,
    )


def list_reviews(db: Session, incident_id: str) -> list[ReviewDecision]:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")

    return list(
        db.scalars(
            select(ReviewDecision)
            .where(ReviewDecision.incident_id == incident_id)
            .order_by(ReviewDecision.timestamp.desc())
        ).all()
    )


def get_review_draft(db: Session, incident_id: str) -> ReviewDraft | None:
    incident = db.scalar(select(Incident.id).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    return db.scalar(select(ReviewDraft).where(ReviewDraft.incident_id == incident_id))


def upsert_review_draft(
    db: Session,
    incident_id: str,
    *,
    reviewer_id: int,
    selected_decision: str | None,
    reason: str | None,
    evidence_checklist: list[str] | None,
    evidence_relied_on: list[str] | None,
    evidence_limitations: str | None,
    missing_evidence_notes: str | None,
    missing_evidence_acknowledged: bool,
) -> ReviewDraft:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    if selected_decision:
        selected_decision = review_policy_service.parse_review_decision(selected_decision).value
    try:
        safe_reason = audit_safety_service.prepare_review_comment(reason)
        safe_checklist = _prepare_safe_items(evidence_checklist)
        safe_evidence = _prepare_safe_items(evidence_relied_on)
        safe_limitations = audit_safety_service.prepare_review_comment(evidence_limitations)
        safe_missing = audit_safety_service.prepare_review_comment(missing_evidence_notes)
    except AuditSafetyError as exc:
        raise UnsafeReviewCommentError(str(exc)) from exc

    draft = db.scalar(select(ReviewDraft).where(ReviewDraft.incident_id == incident_id))
    if draft is None:
        draft = ReviewDraft(incident_id=incident_id)
        db.add(draft)
    draft.selected_decision = selected_decision
    draft.reason = safe_reason
    draft.evidence_checklist = safe_checklist
    draft.evidence_relied_on = safe_evidence
    draft.evidence_limitations = safe_limitations
    draft.missing_evidence_notes = safe_missing
    draft.missing_evidence_acknowledged = missing_evidence_acknowledged
    draft.last_updated_by = reviewer_id
    draft.last_updated_at = datetime.now(timezone.utc)

    reviewer = db.get(User, reviewer_id)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_REVIEW_DRAFT_SAVED,
        actor_id=reviewer_id,
        actor_email=reviewer.email if reviewer else None,
        actor_role=reviewer.role.value if reviewer else None,
        target_type="incident",
        target_id=incident_id,
        details={
            "incident_id": incident_id,
            "selected_decision": selected_decision,
            "checklist_item_count": len(safe_checklist),
            "draft_only": True,
        },
    )
    db.commit()
    db.refresh(draft)
    return draft


def delete_review_draft(db: Session, incident_id: str, *, reviewer_id: int) -> bool:
    incident = db.scalar(select(Incident.id).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    draft = db.scalar(select(ReviewDraft).where(ReviewDraft.incident_id == incident_id))
    if draft is None:
        return False
    db.delete(draft)
    reviewer = db.get(User, reviewer_id)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_REVIEW_DRAFT_DELETED,
        actor_id=reviewer_id,
        actor_email=reviewer.email if reviewer else None,
        actor_role=reviewer.role.value if reviewer else None,
        target_type="incident",
        target_id=incident_id,
        details={"incident_id": incident_id, "draft_only": True},
    )
    db.commit()
    return True
