from __future__ import annotations

from datetime import datetime, timezone

import re
from functools import lru_cache
from pathlib import Path
from string import Template
from uuid import uuid4

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings, resolve_rules_dir
from app.models.evidence_file import EvidenceFile
from app.models.preventive_control import PreventiveControl, PreventiveControlEvidenceLink
from app.models.root_cause_score import RootCauseScore
from app.services import audit_safety_service, audit_service


class PreventiveControlError(ValueError):
    pass


class PreventiveControlNotFoundError(PreventiveControlError):
    pass


def _safe_reason(reason: str) -> str:
    value = audit_safety_service.prepare_review_comment(reason)
    if not value:
        raise PreventiveControlError("A reason is required.")
    return value


def _safe_component(value: str | None) -> str:
    candidate = (value or "affected-component").strip()
    return candidate if re.fullmatch(r"[A-Za-z0-9_./:-]{1,255}", candidate) else "affected-component"


def _safe_reference(value: str, *, field: str, maximum: int = 512) -> str:
    candidate = value.strip()
    if not candidate or len(candidate) > maximum or not re.fullmatch(r"[A-Za-z0-9_./:@#-]+", candidate):
        raise PreventiveControlError(f"{field} contains unsupported characters.")
    return candidate


def _root_cause_key(item: RootCauseScore) -> str:
    for source in (item.likely_root_cause, item.cause_name):
        key = re.sub(r"[^a-z0-9]+", "_", (source or "").casefold()).strip("_")
        if key:
            return key
    return ""


@lru_cache(maxsize=4)
def _load_templates(path_text: str) -> dict:
    path = Path(path_text)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PreventiveControlError("Preventive-control templates are unavailable.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("templates"), dict):
        raise PreventiveControlError("Preventive-control templates are invalid.")
    return data


def load_templates(path: str | Path | None = None) -> dict:
    resolved = Path(path) if path else resolve_rules_dir() / "preventive_control_templates.yaml"
    return _load_templates(str(resolved.resolve()))


def template_proposals(
    root_cause: RootCauseScore,
    *,
    control_types: list[str] | None = None,
    affected_component: str | None = None,
    rules: dict | None = None,
) -> list[dict]:
    rules = rules or load_templates()
    templates = rules.get("templates", {})
    candidates = templates.get(_root_cause_key(root_cause), [])
    selected = set(control_types or [])
    component = _safe_component(affected_component)
    proposals: list[dict] = []
    for item in candidates:
        if selected and item.get("control_type") not in selected:
            continue
        proposals.append(
            {
                "control_type": str(item["control_type"]),
                "control_name": str(item["control_name"]),
                "control_description": str(item["description"]),
                "generated_content": Template(str(item["content"])).safe_substitute(component=component),
                "language": item.get("language"),
                "source": "deterministic_template",
                "generation_method": _root_cause_key(root_cause),
                "ruleset_version": str(rules.get("version") or "unknown"),
            }
        )
    return proposals


def _get_control(db: Session, control_id: str, *, lock: bool = False) -> PreventiveControl:
    stmt = select(PreventiveControl).where(PreventiveControl.control_id == control_id)
    if lock:
        stmt = stmt.with_for_update()
    item = db.scalar(stmt)
    if item is None:
        raise PreventiveControlNotFoundError("Preventive control was not found.")
    return item


def list_controls(db: Session, incident_id: str) -> list[PreventiveControl]:
    return list(db.scalars(select(PreventiveControl).where(PreventiveControl.incident_id == incident_id).order_by(PreventiveControl.created_at.desc())).all())


def generate_controls(
    db: Session,
    incident_id: str,
    *,
    root_cause_id: str,
    actor_id: int,
    control_types: list[str] | None = None,
    affected_component: str | None = None,
    use_ai: bool = False,
) -> list[PreventiveControl]:
    settings = get_settings()
    if not getattr(settings, "preventive_control_generation_enabled", True):
        raise PreventiveControlError("Preventive-control generation is disabled.")
    if use_ai:
        if not getattr(settings, "preventive_control_ai_generation_enabled", False):
            raise PreventiveControlError("AI control generation is disabled.")
        raise PreventiveControlError("No approved masked AI control provider is configured.")
    root_cause = db.scalar(select(RootCauseScore).where(RootCauseScore.root_cause_id == root_cause_id, RootCauseScore.incident_id == incident_id))
    if root_cause is None:
        raise PreventiveControlError("Root-cause record was not found for this incident.")
    proposals = template_proposals(root_cause, control_types=control_types, affected_component=affected_component)
    if not proposals:
        raise PreventiveControlError("No deterministic template matches this reviewed likely cause.")
    created: list[PreventiveControl] = []
    for proposal in proposals:
        existing = db.scalar(select(PreventiveControl).where(
            PreventiveControl.incident_id == incident_id,
            PreventiveControl.root_cause_id == root_cause_id,
            PreventiveControl.control_type == proposal["control_type"],
            PreventiveControl.control_name == proposal["control_name"],
            PreventiveControl.status.notin_(["retired", "rejected"]),
        ))
        if existing:
            created.append(existing)
            continue
        item = PreventiveControl(
            control_id=f"CTRL-{uuid4().hex[:20].upper()}",
            incident_id=incident_id,
            root_cause_id=root_cause_id,
            created_by=actor_id,
            **proposal,
        )
        db.add(item)
        created.append(item)
    audit_service.log_action(db, action="preventive_controls_generated", actor_id=actor_id, target_type="incident", target_id=incident_id, details={"incident_id": incident_id, "root_cause_id": root_cause_id, "control_ids": [item.control_id for item in created], "generation_method": "deterministic_template"})
    db.commit()
    for item in created:
        db.refresh(item)
    return created


def review_control(db: Session, control_id: str, *, actor_id: int, decision: str, reason: str) -> PreventiveControl:
    item = _get_control(db, control_id, lock=True)
    if item.status != "proposed":
        raise PreventiveControlError("Only a proposed control can be reviewed.")
    if item.created_by == actor_id:
        raise PreventiveControlError("The proposer cannot review the same control.")
    item.reviewed_by = actor_id
    item.reviewed_at = datetime.now(timezone.utc)
    item.status = "reviewed" if decision == "accepted" else "changes_required"
    item.rejection_reason = None if decision == "accepted" else _safe_reason(reason)
    safe_reason = _safe_reason(reason)
    audit_service.log_action(db, action="preventive_control_reviewed", actor_id=actor_id, target_type="preventive_control", target_id=control_id, details={"incident_id": item.incident_id, "decision": decision, "reason": safe_reason})
    db.commit()
    db.refresh(item)
    return item


def approve_control(db: Session, control_id: str, *, actor_id: int, reason: str) -> PreventiveControl:
    item = _get_control(db, control_id, lock=True)
    if item.status != "reviewed":
        raise PreventiveControlError("The control must be accepted in review before approval.")
    if actor_id in {item.created_by, item.reviewed_by}:
        raise PreventiveControlError("Approval requires a separate authorised user.")
    item.status = "approved"
    item.approved_by = actor_id
    item.approved_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="preventive_control_approved", actor_id=actor_id, target_type="preventive_control", target_id=control_id, details={"incident_id": item.incident_id, "reason": _safe_reason(reason)})
    db.commit()
    db.refresh(item)
    return item


def implement_control(db: Session, control_id: str, *, actor_id: int, implementation_reference: str, remediation_action_id: str | None, reason: str) -> PreventiveControl:
    item = _get_control(db, control_id, lock=True)
    if item.status != "approved":
        raise PreventiveControlError("Only an approved control can be implemented.")
    item.status = "implemented"
    item.implementation_reference = _safe_reference(implementation_reference, field="Implementation reference")
    item.remediation_action_id = remediation_action_id
    item.implemented_by = actor_id
    item.implemented_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="preventive_control_implemented", actor_id=actor_id, target_type="preventive_control", target_id=control_id, details={"incident_id": item.incident_id, "implementation_reference": item.implementation_reference, "remediation_action_id": remediation_action_id, "reason": _safe_reason(reason)})
    db.commit()
    db.refresh(item)
    return item


def verify_control(db: Session, control_id: str, *, actor_id: int, verification_method: str, verification_result: str, passed: bool, retest_evidence_ids: list[str], reason: str) -> PreventiveControl:
    item = _get_control(db, control_id, lock=True)
    if item.status != "implemented":
        raise PreventiveControlError("Only an implemented control can be verified.")
    if item.implemented_by == actor_id:
        raise PreventiveControlError("The implementer cannot verify the same control.")
    evidence_ids = sorted(set(retest_evidence_ids))
    if evidence_ids:
        existing = set(db.scalars(select(EvidenceFile.evidence_id).where(EvidenceFile.evidence_id.in_(evidence_ids))).all())
        missing = sorted(set(evidence_ids) - existing)
        if missing:
            raise PreventiveControlError("One or more retest evidence references were not found.")
        for evidence_id in evidence_ids:
            link = db.scalar(select(PreventiveControlEvidenceLink).where(PreventiveControlEvidenceLink.control_id == control_id, PreventiveControlEvidenceLink.evidence_id == evidence_id, PreventiveControlEvidenceLink.evidence_role == "retest"))
            if link is None:
                db.add(PreventiveControlEvidenceLink(control_id=control_id, evidence_id=evidence_id, evidence_role="retest"))
    item.status = "verified" if passed else "verification_failed"
    item.verification_status = "passed" if passed else "failed"
    item.verification_method = _safe_reference(verification_method, field="Verification method", maximum=128)
    item.verification_result = _safe_reason(verification_result)
    item.failure_reason = None if passed else _safe_reason(reason)
    item.verified_by = actor_id
    item.verified_at = datetime.now(timezone.utc)
    audit_service.log_action(db, action="preventive_control_verified" if passed else "preventive_control_verification_failed", actor_id=actor_id, target_type="preventive_control", target_id=control_id, details={"incident_id": item.incident_id, "verification_method": item.verification_method, "verification_status": item.verification_status, "evidence_ids": evidence_ids, "reason": _safe_reason(reason)})
    db.commit()
    db.refresh(item)
    return item


def retire_control(db: Session, control_id: str, *, actor_id: int, reason: str) -> PreventiveControl:
    item = _get_control(db, control_id, lock=True)
    if item.status in {"retired", "rejected"}:
        raise PreventiveControlError("The control is already inactive.")
    item.status = "retired"
    item.retired_by = actor_id
    item.retired_at = datetime.now(timezone.utc)
    item.retirement_reason = _safe_reason(reason)
    audit_service.log_action(db, action="preventive_control_retired", actor_id=actor_id, target_type="preventive_control", target_id=control_id, details={"incident_id": item.incident_id, "reason": item.retirement_reason})
    db.commit()
    db.refresh(item)
    return item


