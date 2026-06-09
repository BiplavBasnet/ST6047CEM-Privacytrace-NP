"""AI Remediation Assistant orchestration."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    AIRemediationSuggestion,
    Detection,
    EvidenceFile,
    FixVerification,
    Incident,
    ReviewDecision,
)
from app.schemas.ai_remediation_schema import (
    AIRemediationDecisionResponse,
    AIRemediationStatusResponse,
    AIRemediationSuggestionListResponse,
    AIRemediationSuggestionRead,
)
from app.services import (
    ai_output_safety_service,
    ai_provider_client,
    ai_safety_gateway,
    audit_service,
    causality_engine,
    report_safety_service,
    restricted_data_policy_service,
    workflow_provenance_service,
)
from app.services.workflow_provenance_service import WorkflowProvenanceError


class AIRemediationError(Exception):
    pass


class AIIncidentNotFoundError(AIRemediationError):
    pass


class AISuggestionNotFoundError(AIRemediationError):
    pass


class AIAssistantDisabledError(AIRemediationError):
    pass


class AIProviderUnavailableError(AIRemediationError):
    pass


class AISafetyBlockedError(AIRemediationError):
    pass


class AISuggestionStateError(AIRemediationError):
    pass


def _new_suggestion_id() -> str:
    return f"AIR-{uuid.uuid4().hex[:12].upper()}"


def _new_remediation_action_id() -> str:
    return f"REM-AI-{uuid.uuid4().hex[:10].upper()}"


def _hash_payload(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def _actor_kwargs(actor_id: int | None, actor_email: str | None, actor_role: str | None) -> dict:
    return {"actor_id": actor_id, "actor_email": actor_email, "actor_role": actor_role}


def _safe_text(value: str | None) -> str | None:
    result = report_safety_service.sanitize_export_text(value)
    return result.value


def get_status() -> AIRemediationStatusResponse:
    settings = get_settings()
    configured = ai_provider_client.provider_configured()
    if not settings.ai_assistant_enabled:
        message = "AI Remediation Assistant is disabled. Manual remediation workflow remains available."
    elif not configured:
        message = "AI Remediation Assistant is enabled but provider configuration is incomplete."
    else:
        message = "AI Remediation Assistant is enabled with safety gateway validation."
    return AIRemediationStatusResponse(
        enabled=settings.ai_assistant_enabled,
        provider_configured=configured,
        model=settings.ai_model or None,
        safety_gateway_enabled=True,
        message=message,
    )


def _latest_value(rows, attr: str) -> str | None:
    if not rows:
        return None
    return str(getattr(rows[0], attr, "")) or None


def build_masked_payload(db: Session, incident_id: str) -> dict[str, Any]:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise AIIncidentNotFoundError(f"Incident not found: {incident_id}")

    detections = db.scalars(
        select(Detection).where(Detection.incident_id == incident_id).order_by(Detection.id.asc())
    ).all()
    evidence = db.scalars(
        select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id).order_by(EvidenceFile.id.asc())
    ).all()
    # Phase N: root-cause analyses are versioned; only the incident's current
    # (latest) analysis batch should feed the AI remediation context.
    scores = causality_engine.list_root_cause_scores(db, incident_id)
    reviews = db.scalars(
        select(ReviewDecision)
        .where(ReviewDecision.incident_id == incident_id)
        .order_by(ReviewDecision.timestamp.desc(), ReviewDecision.id.desc())
    ).all()
    fixes = db.scalars(
        select(FixVerification)
        .where(FixVerification.incident_id == incident_id)
        .order_by(FixVerification.timestamp.desc(), FixVerification.id.desc())
    ).all()

    top = scores[0] if scores else None
    payload = {
        "incident_id": incident.incident_id,
        "title": _safe_text(incident.title),
        "affected_service": _safe_text(incident.affected_service),
        "affected_endpoint": _safe_text(incident.affected_endpoint),
        "severity": incident.severity.value if incident.severity else None,
        "status": incident.status.value if incident.status else None,
        "safe_incident_summary": _safe_text(incident.summary),
        "masked_detections": [
            {
                "detection_id": d.detection_id,
                "sensitive_type": d.sensitive_type,
                "masked_value": _safe_text(d.masked_value),
                "severity": d.severity.value if d.severity else None,
                "evidence_id": d.evidence_id,
            }
            for d in detections
            if not restricted_data_policy_service.is_restricted_category(
                d.sensitive_type, channel="external_ai"
            )
        ],
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "evidence_type": e.evidence_type.value,
                "source_system": _safe_text(e.source_system),
                "parsing_status": e.parsing_status.value,
            }
            for e in evidence
        ],
        "likely_root_cause_category": _safe_text(top.likely_root_cause if top else None),
        "confidence_level": _safe_text(top.confidence_band if top else None),
        "score_breakdown_summary": list((top.score_breakdown if top else []) or [])[:8],
        "missing_evidence": list((top.missing_evidence if top else []) or []),
        "contradicting_evidence": list((top.contradicting_evidence if top else []) or [])[:8],
        "human_review_status": _latest_value(reviews, "decision") or "pending",
        "fix_verification_status": fixes[0].verification_status.value if fixes else "not_completed",
        "safe_remediation_context": _safe_text(top.recommended_fix if top else None),
    }
    payload, _restricted_present = restricted_data_policy_service.sanitize_payload(
        payload,
        channel="external_ai",
    )
    safety = ai_safety_gateway.validate_masked_ai_input(payload)
    if not safety.safe:
        raise AISafetyBlockedError(safety.message)
    return payload


def _to_read(row: AIRemediationSuggestion) -> AIRemediationSuggestionRead:
    return AIRemediationSuggestionRead(
        suggestion_id=row.suggestion_id,
        incident_id=row.incident_id,
        requested_by_user_id=row.requested_by_user_id,
        requested_at=row.requested_at,
        ai_provider=row.ai_provider,
        ai_model=row.ai_model,
        input_safety_status=row.input_safety_status,
        output_safety_status=row.output_safety_status,
        status=row.status,
        masked_input_summary_hash=row.masked_input_summary_hash,
        suggestion_summary=row.suggestion_summary,
        likely_issue_area=row.likely_issue_area,
        remediation_actions=[str(x) for x in (row.remediation_actions or [])],
        code_or_config_areas=[str(x) for x in (row.code_or_config_areas or [])],
        suggested_tests=[str(x) for x in (row.suggested_tests or [])],
        retest_evidence_required=[str(x) for x in (row.retest_evidence_required or [])],
        limitations=[str(x) for x in (row.limitations or [])],
        human_review_required=row.human_review_required,
        reviewer_decision=row.reviewer_decision,
        reviewer_notes=row.reviewer_notes,
        accepted_as_remediation_action_id=row.accepted_as_remediation_action_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _create_suggestion_row(
    db: Session,
    *,
    incident_id: str,
    requested_by_user_id: int | None,
    provider: str | None,
    model: str | None,
    input_safety_status: str,
    output_safety_status: str,
    status: str,
    masked_input_summary_hash: str,
    payload: dict[str, Any] | None = None,
) -> AIRemediationSuggestion:
    data = payload or {}
    row = AIRemediationSuggestion(
        suggestion_id=_new_suggestion_id(),
        incident_id=incident_id,
        requested_by_user_id=requested_by_user_id,
        requested_at=datetime.now(UTC),
        ai_provider=provider,
        ai_model=model,
        input_safety_status=input_safety_status,
        output_safety_status=output_safety_status,
        status=status,
        masked_input_summary_hash=masked_input_summary_hash,
        suggestion_summary=data.get("suggestion_summary"),
        likely_issue_area=data.get("likely_issue_area"),
        remediation_actions=list(data.get("remediation_actions") or []),
        code_or_config_areas=list(data.get("code_or_config_areas") or []),
        suggested_tests=list(data.get("suggested_tests") or []),
        retest_evidence_required=list(data.get("retest_evidence_required") or []),
        limitations=list(data.get("limitations") or []),
        human_review_required=True,
    )
    db.add(row)
    db.flush()
    return row


def generate_suggestion(
    db: Session,
    incident_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> AIRemediationSuggestionRead:
    settings = get_settings()
    if not settings.ai_assistant_enabled:
        raise AIAssistantDisabledError("AI Remediation Assistant is disabled. You can still create remediation actions manually.")

    try:
        payload = build_masked_payload(db, incident_id)
    except AISafetyBlockedError as exc:
        blocked_hash = _hash_payload({"incident_id": incident_id, "blocked": "input_unsafe"})
        row = _create_suggestion_row(
            db,
            incident_id=incident_id,
            requested_by_user_id=actor_id,
            provider=settings.ai_provider,
            model=settings.ai_model or None,
            input_safety_status="blocked_input_unsafe",
            output_safety_status="not_generated",
            status="blocked_input_unsafe",
            masked_input_summary_hash=blocked_hash,
        )
        audit_service.log_action(
            db,
            action="ai_remediation_input_blocked",
            target_type="ai_remediation_suggestion",
            target_id=row.suggestion_id,
            details={"incident_id": incident_id, "reason": "unsafe_input"},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit()
        raise AISafetyBlockedError(str(exc)) from exc
    input_hash = _hash_payload(payload)
    audit_service.log_action(
        db,
        action="ai_remediation_suggestion_requested",
        target_type="incident",
        target_id=incident_id,
        details={"masked_input_summary_hash": input_hash},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )

    try:
        provider_result = ai_provider_client.generate_remediation_suggestion(payload)
    except ai_provider_client.AIProviderError as exc:
        row = _create_suggestion_row(
            db,
            incident_id=incident_id,
            requested_by_user_id=actor_id,
            provider=settings.ai_provider,
            model=settings.ai_model or None,
            input_safety_status="safe_masked_input",
            output_safety_status="not_generated",
            status="failed",
            masked_input_summary_hash=input_hash,
        )
        audit_service.log_action(
            db,
            action="ai_remediation_provider_failed",
            target_type="ai_remediation_suggestion",
            target_id=row.suggestion_id,
            details={"reason": "provider_unavailable"},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit()
        raise AIProviderUnavailableError(str(exc)) from exc

    normalized = ai_output_safety_service.normalize_suggestion_payload(provider_result.content)
    safety = ai_output_safety_service.validate_ai_output(normalized)
    if not safety.safe:
        row = _create_suggestion_row(
            db,
            incident_id=incident_id,
            requested_by_user_id=actor_id,
            provider=provider_result.provider,
            model=provider_result.model,
            input_safety_status="safe_masked_input",
            output_safety_status=safety.status,
            status="blocked_output_unsafe",
            masked_input_summary_hash=input_hash,
        )
        audit_service.log_action(
            db,
            action="ai_remediation_output_blocked",
            target_type="ai_remediation_suggestion",
            target_id=row.suggestion_id,
            details={"violation_count": len(safety.violation_codes)},
            **_actor_kwargs(actor_id, actor_email, actor_role),
        )
        db.commit()
        raise AISafetyBlockedError(safety.message)

    row = _create_suggestion_row(
        db,
        incident_id=incident_id,
        requested_by_user_id=actor_id,
        provider=provider_result.provider,
        model=provider_result.model,
        input_safety_status="safe_masked_input",
        output_safety_status=safety.status,
        status="generated",
        masked_input_summary_hash=input_hash,
        payload=normalized,
    )
    audit_service.log_action(
        db,
        action="ai_remediation_suggestion_generated",
        target_type="ai_remediation_suggestion",
        target_id=row.suggestion_id,
        details={"incident_id": incident_id, "masked_input_summary_hash": input_hash},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    db.refresh(row)
    return _to_read(row)


def list_suggestions(db: Session, incident_id: str) -> AIRemediationSuggestionListResponse:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise AIIncidentNotFoundError(f"Incident not found: {incident_id}")
    rows = db.scalars(
        select(AIRemediationSuggestion)
        .where(AIRemediationSuggestion.incident_id == incident_id)
        .order_by(AIRemediationSuggestion.requested_at.desc(), AIRemediationSuggestion.id.desc())
    ).all()
    return AIRemediationSuggestionListResponse(
        incident_id=incident_id,
        suggestions=[_to_read(row) for row in rows],
        total=len(rows),
    )


def get_suggestion(db: Session, suggestion_id: str) -> AIRemediationSuggestionRead:
    row = db.scalar(select(AIRemediationSuggestion).where(AIRemediationSuggestion.suggestion_id == suggestion_id))
    if not row:
        raise AISuggestionNotFoundError(f"AI remediation suggestion not found: {suggestion_id}")
    return _to_read(row)


def _get_row(db: Session, suggestion_id: str) -> AIRemediationSuggestion:
    row = db.scalar(select(AIRemediationSuggestion).where(AIRemediationSuggestion.suggestion_id == suggestion_id))
    if not row:
        raise AISuggestionNotFoundError(f"AI remediation suggestion not found: {suggestion_id}")
    return row


def accept_suggestion(
    db: Session,
    suggestion_id: str,
    *,
    reviewer_notes: str | None,
    create_remediation_action: bool,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> AIRemediationDecisionResponse:
    row = _get_row(db, suggestion_id)
    if create_remediation_action:
        try:
            workflow_provenance_service.assert_current_governed_remediation_permission(
                db,
                row.incident_id,
                actor_id=actor_id,
                require_active_human_actor=True,
            )
        except WorkflowProvenanceError as exc:
            raise AISuggestionStateError(str(exc)) from exc
    if row.status not in {"generated", "edited_by_reviewer", "accepted_by_reviewer"}:
        raise AISuggestionStateError("Only generated or edited suggestions can be accepted.")
    safety = ai_output_safety_service.validate_reviewer_text(reviewer_notes or "")
    if not safety.safe:
        raise AISafetyBlockedError("Reviewer notes failed safety validation.")
    row.reviewer_decision = "accepted"
    row.reviewer_notes = reviewer_notes
    row.status = "accepted_by_reviewer"
    # Legacy suggestions remain advisory; canonical actions use diagnosis acceptance.
    row.accepted_as_remediation_action_id = None
    db.add(row)
    audit_service.log_action(
        db,
        action="ai_remediation_suggestion_accepted",
        target_type="ai_remediation_suggestion",
        target_id=row.suggestion_id,
        details={
            "incident_id": row.incident_id,
            "create_remediation_action": False,
            "remediation_action_id": None,
            "fix_verification_status": "not_changed",
            "incident_closure": "not_changed",
        },
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return AIRemediationDecisionResponse(
        suggestion_id=row.suggestion_id,
        status=row.status,
        reviewer_decision="accepted",
        accepted_as_remediation_action_id=row.accepted_as_remediation_action_id,
        message="AI suggestion accepted as advisory remediation guidance. Fix verification remains required.",
    )


def edit_suggestion(
    db: Session,
    suggestion_id: str,
    *,
    edited_remediation_actions: list[str],
    reviewer_notes: str | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> AIRemediationDecisionResponse:
    row = _get_row(db, suggestion_id)
    safety = ai_output_safety_service.validate_reviewer_text({"actions": edited_remediation_actions, "notes": reviewer_notes})
    if not safety.safe:
        raise AISafetyBlockedError("Edited suggestion failed safety validation.")
    row.remediation_actions = [str(item)[:1000] for item in edited_remediation_actions]
    row.reviewer_notes = reviewer_notes
    row.reviewer_decision = "edited"
    row.status = "edited_by_reviewer"
    db.add(row)
    audit_service.log_action(
        db,
        action="ai_remediation_suggestion_edited",
        target_type="ai_remediation_suggestion",
        target_id=row.suggestion_id,
        details={"incident_id": row.incident_id, "fix_verification_status": "not_changed"},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return AIRemediationDecisionResponse(
        suggestion_id=row.suggestion_id,
        status=row.status,
        reviewer_decision="edited",
        accepted_as_remediation_action_id=row.accepted_as_remediation_action_id,
        message="AI suggestion edited by reviewer. Human approval and retest evidence are still required.",
    )


def reject_suggestion(
    db: Session,
    suggestion_id: str,
    *,
    reason: str,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> AIRemediationDecisionResponse:
    row = _get_row(db, suggestion_id)
    safety = ai_output_safety_service.validate_reviewer_text(reason)
    if not safety.safe:
        raise AISafetyBlockedError("Rejection reason failed safety validation.")
    row.reviewer_decision = "rejected"
    row.reviewer_notes = reason
    row.status = "rejected_by_reviewer"
    db.add(row)
    audit_service.log_action(
        db,
        action="ai_remediation_suggestion_rejected",
        target_type="ai_remediation_suggestion",
        target_id=row.suggestion_id,
        details={"incident_id": row.incident_id, "incident_status": "not_changed"},
        **_actor_kwargs(actor_id, actor_email, actor_role),
    )
    db.commit()
    return AIRemediationDecisionResponse(
        suggestion_id=row.suggestion_id,
        status=row.status,
        reviewer_decision="rejected",
        accepted_as_remediation_action_id=row.accepted_as_remediation_action_id,
        message="AI suggestion rejected. Incident workflow remains under human control.",
    )
