from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.breach_decision import BreachDecisionFactor, BreachDecisionRecord
from app.models.incident import Incident
from app.models.privacy_impact import PrivacyImpactAssessment
from app.schemas.breach_decision_schema import (
    BreachDecisionCreate, BreachDecisionReviewRequest, BreachDecisionSupersedeRequest,
)
from app.services import audit_service, audit_safety_service, integrity_ledger_service


class BreachDecisionError(Exception):
    pass


class BreachDecisionNotFoundError(BreachDecisionError):
    pass


class BreachDecisionStateError(BreachDecisionError):
    pass


APPROVED_SUPERSESSION_FIELDS = frozenset({"status", "superseded_by_record_id"})


def validate_approved_transition(
    *, current_status: str, next_status: str, changed_fields: set[str]
) -> None:
    if current_status != "approved":
        return
    if (
        next_status != "superseded"
        or changed_fields != APPROVED_SUPERSESSION_FIELDS
    ):
        raise BreachDecisionStateError(
            "Approved decisions are immutable; create a controlled superseding version."
        )


def _new_id() -> str:
    return f"BDR-{uuid.uuid4().hex[:20].upper()}"


def _get(db: Session, decision_id: str, *, lock: bool = False) -> BreachDecisionRecord:
    stmt = select(BreachDecisionRecord).options(selectinload(BreachDecisionRecord.factors)).where(BreachDecisionRecord.decision_id == decision_id)
    if lock:
        stmt = stmt.with_for_update()
    item = db.scalar(stmt)
    if item is None:
        raise BreachDecisionNotFoundError(f"Breach decision not found: {decision_id}")
    return item


def _validate_payload(body: BreachDecisionCreate) -> None:
    if body.human_override_present and not (body.human_override_reason or "").strip():
        raise BreachDecisionStateError("A human override requires a reason.")
    for factor in body.factors:
        if not factor.evidence_ids and not factor.reason.strip():
            raise BreachDecisionStateError(f"Factor {factor.factor_code} requires evidence or an explicit reason.")


def validate_approver_separation(
    *, created_by: int | None, reviewed_by: int | None, actor_id: int
) -> None:
    if actor_id in {created_by, reviewed_by}:
        raise BreachDecisionStateError(
            "The decision approver must be independent of its creator and reviewer."
        )


def _create_record(
    db: Session, incident_id: str, body: BreachDecisionCreate, *, actor_id: int | None,
    decision_version: int, supersedes_record_id: str | None,
    decision_id: str | None = None,
    superseded_by_record_id: str | None = None,
) -> BreachDecisionRecord:
    _validate_payload(body)
    assessment = db.scalar(select(PrivacyImpactAssessment).where(PrivacyImpactAssessment.assessment_id == body.assessment_id))
    if assessment is None or assessment.incident_id != incident_id:
        raise BreachDecisionStateError("The assessment must exist and belong to the incident.")
    if assessment.status != "approved":
        raise BreachDecisionStateError("The assessment must be approved before a breach decision is created.")
    values = body.model_dump(exclude={"factors"})
    values["human_override_reason"] = audit_safety_service.prepare_review_comment(body.human_override_reason)
    record = BreachDecisionRecord(
        decision_id=decision_id or _new_id(), incident_id=incident_id, decision_version=decision_version,
        status="draft", created_by=actor_id, supersedes_record_id=supersedes_record_id,
        superseded_by_record_id=superseded_by_record_id, **values,
    )
    db.add(record)
    db.flush()
    for factor in body.factors:
        db.add(BreachDecisionFactor(
            decision_record_id=record.decision_id, review_status="pending", **factor.model_dump()
        ))
    db.flush()
    return _get(db, record.decision_id)


def create_decision(
    db: Session,
    incident_id: str,
    body: BreachDecisionCreate,
    *,
    actor_id: int | None,
    commit: bool = True,
) -> BreachDecisionRecord:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id).with_for_update())
    if incident is None:
        raise BreachDecisionNotFoundError(f"Incident not found: {incident_id}")
    current = db.scalar(select(BreachDecisionRecord).where(
        BreachDecisionRecord.incident_id == incident_id,
        BreachDecisionRecord.superseded_by_record_id.is_(None),
    ).with_for_update())
    if current is not None:
        raise BreachDecisionStateError("A current decision exists; create the next version through supersession.")
    version = int(db.scalar(select(func.coalesce(func.max(BreachDecisionRecord.decision_version), 0)).where(BreachDecisionRecord.incident_id == incident_id)) or 0) + 1
    record = _create_record(db, incident_id, body, actor_id=actor_id, decision_version=version, supersedes_record_id=None)
    audit_service.log_action(db, action="breach_decision_created", actor_id=actor_id, target_type="breach_decision", target_id=record.decision_id,
                             details={"incident_id": incident_id, "decision_version": version})
    if commit:
        db.commit()
        db.refresh(record)
    else:
        db.flush()
    return _get(db, record.decision_id)


def list_decisions(db: Session, incident_id: str) -> list[BreachDecisionRecord]:
    return list(db.scalars(select(BreachDecisionRecord).options(selectinload(BreachDecisionRecord.factors)).where(
        BreachDecisionRecord.incident_id == incident_id
    ).order_by(BreachDecisionRecord.decision_version.desc())).unique().all())


def get_decision(db: Session, decision_id: str) -> BreachDecisionRecord:
    return _get(db, decision_id)


def review_decision(
    db: Session,
    decision_id: str,
    body: BreachDecisionReviewRequest,
    *,
    actor_id: int,
    commit: bool = True,
) -> BreachDecisionRecord:
    item = _get(db, decision_id, lock=True)
    if item.status not in {"draft", "changes_required"}:
        raise BreachDecisionStateError("Only a draft decision can be reviewed.")
    factor_ids = {factor.id for factor in item.factors}
    unknown_factor_ids = set(body.factor_review_statuses) - factor_ids
    if unknown_factor_ids:
        raise BreachDecisionStateError("The review contains unknown decision factor IDs.")
    for factor in item.factors:
        factor.review_status = body.factor_review_statuses.get(factor.id, "accepted" if body.decision == "accepted" else "changes_required")
    accepted = body.decision == "accepted" and all(factor.review_status == "accepted" for factor in item.factors)
    item.status = "reviewed" if accepted else "changes_required"
    item.reviewed_by = actor_id
    item.reviewed_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="breach_decision_reviewed", actor_id=actor_id, target_type="breach_decision", target_id=item.decision_id,
                             details={"incident_id": item.incident_id, "decision": body.decision, "reason": body.reason})
    if commit:
        db.commit()
        db.refresh(item)
    else:
        db.flush()
    return _get(db, item.decision_id)


def approve_decision(
    db: Session,
    decision_id: str,
    *,
    actor_id: int,
    reason: str,
    commit: bool = True,
) -> BreachDecisionRecord:
    item = _get(db, decision_id, lock=True)
    if item.status != "reviewed":
        raise BreachDecisionStateError("The decision must be reviewed before approval.")
    validate_approver_separation(
        created_by=item.created_by,
        reviewed_by=item.reviewed_by,
        actor_id=actor_id,
    )
    integrity_record_id = f"ILR-{uuid.uuid4().hex[:20].upper()}"
    item.status = "approved"
    item.approved_by = actor_id
    item.approved_at = datetime.now(timezone.utc)
    item.integrity_record_id = integrity_record_id
    ledger = integrity_ledger_service.append_record(
        db, record_type="breach_decision", record_id=item.decision_id,
        canonical_content=integrity_ledger_service.breach_decision_integrity_content(item),
        scope_type="incident", scope_id=item.incident_id,
        integrity_record_id=integrity_record_id,
    )
    if ledger.integrity_record_id != integrity_record_id:
        raise BreachDecisionStateError("The decision integrity record could not be linked safely.")
    if item.breach_determination in {"suspected", "confirmed"}:
        from app.services import privacy_breach_alert_service

        assessment = db.scalar(
            select(PrivacyImpactAssessment).where(
                PrivacyImpactAssessment.assessment_id == item.assessment_id
            )
        )
        privacy_breach_alert_service.evaluate_assessment(db, assessment, actor_id=actor_id)
    audit_service.log_action(db, action="breach_decision_approved", actor_id=actor_id, target_type="breach_decision", target_id=item.decision_id,
                             details={"incident_id": item.incident_id, "decision_version": item.decision_version, "reason": reason})
    if commit:
        db.commit()
        db.refresh(item)
    else:
        db.flush()
    return _get(db, item.decision_id)


def supersede_decision(
    db: Session,
    decision_id: str,
    body: BreachDecisionSupersedeRequest,
    *,
    actor_id: int,
    commit: bool = True,
) -> BreachDecisionRecord:
    old = _get(db, decision_id, lock=True)
    if old.superseded_by_record_id is not None or old.status != "approved":
        raise BreachDecisionStateError("Only the current approved decision can be superseded.")
    db.scalar(select(Incident).where(Incident.incident_id == old.incident_id).with_for_update())
    validate_approved_transition(
        current_status=old.status,
        next_status="superseded",
        changed_fields={"status", "superseded_by_record_id"},
    )
    replacement_id = _new_id()
    replacement = _create_record(
        db, old.incident_id, body.replacement, actor_id=actor_id,
        decision_version=old.decision_version + 1, supersedes_record_id=old.decision_id,
        decision_id=replacement_id, superseded_by_record_id=old.decision_id,
    )
    old.superseded_by_record_id = replacement_id
    old.status = "superseded"
    db.flush()
    replacement.superseded_by_record_id = None
    db.flush()
    audit_service.log_action(db, action="breach_decision_superseded", actor_id=actor_id, target_type="breach_decision", target_id=old.decision_id,
                             details={"incident_id": old.incident_id, "new_decision_id": replacement.decision_id, "reason": body.reason})
    if commit:
        db.commit()
        db.refresh(replacement)
    else:
        db.flush()
    return _get(db, replacement.decision_id)


def decision_to_comparable(item: BreachDecisionRecord) -> dict[str, Any]:
    return {
        "decision_id": item.decision_id,
        "taxonomy_version": getattr(item, "taxonomy_version", None),
        "combination_ruleset_version": getattr(item, "combination_ruleset_version", None),
        "exposure_profile_ids": sorted(set(getattr(item, "exposure_profile_ids", None) or [])),
        "internal_only_restrictions": sorted(set(getattr(item, "internal_only_restrictions", None) or [])),
        "input_evidence_ids": sorted(set(item.input_evidence_ids or [])),
        "severity_result": item.severity_result or {}, "privacy_harm_result": item.privacy_harm_result or {},
        "containment_recommendations": item.containment_recommendations or [],
        "customer_notification_recommendation": item.customer_notification_recommendation or {},
        "uncertainties": item.uncertainties or [], "human_override_present": item.human_override_present,
        "human_override_reason": item.human_override_reason,
        "factors": [{"factor_code": f.factor_code, "direction": f.direction, "score_contribution": f.score_contribution,
                     "evidence_ids": sorted(set(f.evidence_ids or [])), "reason": f.reason} for f in item.factors],
    }


def compare_decision_values(current: dict, previous: dict | None) -> dict:
    previous = previous or {}
    current_evidence, previous_evidence = set(current.get("input_evidence_ids") or []), set(previous.get("input_evidence_ids") or [])
    previous_factors = {f["factor_code"]: f for f in previous.get("factors") or []}
    current_factors = {f["factor_code"]: f for f in current.get("factors") or []}
    changed_factors = []
    for code in sorted(set(previous_factors) | set(current_factors)):
        if previous_factors.get(code) != current_factors.get(code):
            changed_factors.append({"factor_code": code, "before": previous_factors.get(code), "after": current_factors.get(code)})
    field_names = ("taxonomy_version", "combination_ruleset_version", "exposure_profile_ids", "internal_only_restrictions", "severity_result", "privacy_harm_result", "containment_recommendations", "customer_notification_recommendation", "uncertainties", "human_override_present", "human_override_reason")
    changed_fields = {name: {"before": previous.get(name), "after": current.get(name)} for name in field_names if previous.get(name) != current.get(name)}
    return {
        "decision_id": current.get("decision_id"), "compared_to_decision_id": previous.get("decision_id"),
        "added_evidence": sorted(current_evidence - previous_evidence), "removed_evidence": sorted(previous_evidence - current_evidence),
        "changed_factors": changed_factors, "changed_fields": changed_fields,
    }


def get_differences(db: Session, decision_id: str) -> dict:
    current = _get(db, decision_id)
    previous = _get(db, current.supersedes_record_id) if current.supersedes_record_id else None
    return compare_decision_values(decision_to_comparable(current), decision_to_comparable(previous) if previous else None)
