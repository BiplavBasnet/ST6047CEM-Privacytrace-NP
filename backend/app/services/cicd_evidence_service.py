"""Privacy-safe structured CI/CD evidence import and correlation."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cicd_evidence import CicdEvidence
from app.models.incident import Incident
from app.models.normalized_event import NormalizedEvent
from app.models.privacy_alert import PrivacyAlert
from app.models.user import User
from app.services import audit_safety_service, audit_service, causality_engine
from app.services.audit_safety_service import AuditSafetyError


class CicdEvidenceError(Exception):
    pass


class IncidentNotFoundError(CicdEvidenceError):
    pass


class CicdEvidenceNotFoundError(CicdEvidenceError):
    pass


class UnsafeCicdEvidenceError(CicdEvidenceError):
    pass


def _safe(value: str | None) -> str | None:
    try:
        return audit_safety_service.prepare_review_comment(value)
    except AuditSafetyError as exc:
        raise UnsafeCicdEvidenceError(str(exc)) from exc


def _safe_list(values: list[str] | None) -> list[str]:
    return [item for item in (_safe(value) for value in values or []) if item]


def _actor(db: Session, actor_id: int | None) -> User | None:
    return db.get(User, actor_id) if actor_id else None


def _assert_incident(db: Session, incident_id: str | None) -> None:
    if not incident_id:
        return
    exists = db.scalar(select(Incident.id).where(Incident.incident_id == incident_id))
    if exists is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")


def _normalise_payload(payload: dict) -> dict:
    return {
        "source_name": _safe(payload.get("source_name")),
        "evidence_type": payload.get("evidence_type"),
        "environment": _safe(payload.get("environment")),
        "service_name": _safe(payload.get("service_name")),
        "pipeline_id": _safe(payload.get("pipeline_id")),
        "deployment_version": _safe(payload.get("deployment_version")),
        "commit_reference": _safe(payload.get("commit_reference")),
        "changed_file_paths_safe": _safe_list(payload.get("changed_file_paths_safe")),
        "change_categories": _safe_list(payload.get("change_categories")),
        "scan_summary_safe": _safe(payload.get("scan_summary_safe")),
        "test_summary_safe": _safe(payload.get("test_summary_safe")),
        "event_time": payload.get("event_time"),
        "linked_incident_id": payload.get("linked_incident_id"),
    }


def _payload_hash(payload: dict) -> str:
    serialisable = {
        key: value.isoformat() if isinstance(value, datetime) else value
        for key, value in payload.items()
    }
    encoded = json.dumps(serialisable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _build_record(db: Session, payload: dict, *, imported_by: int | None) -> CicdEvidence:
    safe = _normalise_payload(payload)
    _assert_incident(db, safe.get("linked_incident_id"))
    record = CicdEvidence(
        cicd_evidence_id=f"CICD-{uuid4().hex[:12].upper()}",
        **safe,
        raw_event_hash=_payload_hash(safe),
        safety_status="safe",
    )
    db.add(record)
    db.flush()
    actor = _actor(db, imported_by)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_CICD_EVIDENCE_IMPORTED,
        actor_id=imported_by,
        actor_email=actor.email if actor else None,
        actor_role=actor.role.value if actor else None,
        target_type="cicd_evidence",
        target_id=record.cicd_evidence_id,
        details={
            "evidence_type": record.evidence_type,
            "source_name": record.source_name,
            "linked_incident_id": record.linked_incident_id,
            "raw_content_stored": False,
        },
    )
    return record


def import_evidence(db: Session, payload: dict, *, imported_by: int | None) -> CicdEvidence:
    record = _build_record(db, payload, imported_by=imported_by)
    db.commit()
    db.refresh(record)
    return record


def import_evidence_batch(
    db: Session, payloads: list[dict], *, imported_by: int | None
) -> list[CicdEvidence]:
    records = [_build_record(db, payload, imported_by=imported_by) for payload in payloads]
    db.commit()
    for record in records:
        db.refresh(record)
    return records


def get_evidence(db: Session, cicd_evidence_id: str) -> CicdEvidence:
    row = db.scalar(
        select(CicdEvidence).where(CicdEvidence.cicd_evidence_id == cicd_evidence_id)
    )
    if row is None:
        raise CicdEvidenceNotFoundError(f"CI/CD evidence not found: {cicd_evidence_id}")
    return row


def list_evidence(
    db: Session,
    *,
    incident_id: str | None = None,
    service_name: str | None = None,
    evidence_type: str | None = None,
    limit: int = 200,
) -> list[CicdEvidence]:
    stmt = select(CicdEvidence).order_by(
        CicdEvidence.received_at.desc(), CicdEvidence.id.desc()
    )
    if incident_id:
        _assert_incident(db, incident_id)
        stmt = stmt.where(CicdEvidence.linked_incident_id == incident_id)
    if service_name:
        stmt = stmt.where(CicdEvidence.service_name == service_name)
    if evidence_type:
        stmt = stmt.where(CicdEvidence.evidence_type == evidence_type)
    return list(db.scalars(stmt.limit(limit)).all())


def link_evidence(
    db: Session,
    cicd_evidence_id: str,
    *,
    incident_id: str,
    linked_by: int | None,
) -> CicdEvidence:
    _assert_incident(db, incident_id)
    row = get_evidence(db, cicd_evidence_id)
    row.linked_incident_id = incident_id
    # Phase N: new CI/CD evidence invalidates any existing root-cause
    # analysis ranking for this incident until it is re-run.
    causality_engine.mark_stale(
        db, incident_id, "CI/CD evidence was linked since the last root-cause analysis."
    )
    actor = _actor(db, linked_by)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_CICD_EVIDENCE_LINKED,
        actor_id=linked_by,
        actor_email=actor.email if actor else None,
        actor_role=actor.role.value if actor else None,
        target_type="cicd_evidence",
        target_id=row.cicd_evidence_id,
        details={"incident_id": incident_id, "correlation_requires_human_review": True},
    )
    db.commit()
    db.refresh(row)
    return row


def _normalise_time(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def correlate_evidence(db: Session, incident_id: str) -> list[dict]:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    alerts = list(
        db.scalars(select(PrivacyAlert).where(PrivacyAlert.linked_incident_id == incident_id)).all()
    )
    events = list(
        db.scalars(select(NormalizedEvent).where(NormalizedEvent.linked_incident_id == incident_id)).all()
    )
    # Phase N: only the incident's current (latest) analysis version should
    # inform CI/CD correlation candidates.
    current_scores = causality_engine.list_root_cause_scores(db, incident_id)
    top_root = (
        sorted(
            current_scores,
            key=lambda row: (row.rank if row.rank is not None else 10_000, -(row.confidence or 0.0)),
        )[0]
        if current_scores
        else None
    )
    environments = {a.environment.lower() for a in alerts if a.environment}
    versions = {e.release_version.lower() for e in events if e.release_version}
    service = (incident.affected_service or "").lower()
    cause_tokens = set((top_root.likely_root_cause if top_root else "").lower().replace("_", " ").split())
    first_seen = _normalise_time(incident.first_seen)
    candidates: list[dict] = []
    for row in list_evidence(db, limit=500):
        score = 0.0
        reasons: list[str] = []
        if row.service_name and service and row.service_name.lower() == service:
            score += 0.35
            reasons.append("Same affected service.")
        if row.environment and row.environment.lower() in environments:
            score += 0.15
            reasons.append("Same environment as a linked alert.")
        if row.deployment_version and row.deployment_version.lower() in versions:
            score += 0.2
            reasons.append("Same deployment version as linked event evidence.")
        event_time = _normalise_time(row.event_time)
        if event_time and first_seen:
            seconds = (first_seen - event_time).total_seconds()
            if 0 <= seconds <= 7 * 24 * 3600:
                score += 0.2
                reasons.append("CI/CD event occurred shortly before the first incident event.")
        category_tokens = set(" ".join(row.change_categories or []).lower().replace("_", " ").split())
        if cause_tokens and category_tokens.intersection(cause_tokens):
            score += 0.1
            reasons.append("Change category overlaps the likely-cause area.")
        if row.linked_incident_id == incident_id:
            score = max(score, 0.6)
            reasons.append("Already linked to this incident by a user.")
        if score > 0:
            candidates.append(
                {
                    "cicd_evidence_id": row.cicd_evidence_id,
                    "score": round(min(score, 1.0), 3),
                    "reasons": list(dict.fromkeys(reasons)),
                    "linked": row.linked_incident_id == incident_id,
                }
            )
    return sorted(candidates, key=lambda item: item["score"], reverse=True)

