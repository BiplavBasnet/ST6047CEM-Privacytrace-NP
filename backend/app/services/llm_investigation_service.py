"""Orchestration for Guarded LLM Investigation Assistant (Phase 7)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import LlmReport, RootCauseScore
from app.services import (
    audit_service,
    field_encryption_service,
    llm_context_service,
    llm_provider_service,
    llm_safety_service,
    template_explanation_service,
)
from app.services.causality_engine import get_incident


@dataclass
class ExplainResult:
    report_id: str
    incident_id: str
    provider_used: str
    model_name: str | None
    safety_status: str
    validation_errors: list[str] = field(default_factory=list)
    output: dict = field(default_factory=dict)
    blocked: bool = False


def generate_report_id() -> str:
    return f"LLM-{uuid.uuid4().hex[:12]}"


def get_report_output_json(report: LlmReport) -> dict:
    """Return decrypted LLM output for internal/API use (server-side only)."""
    if report.is_encrypted and report.output_encrypted:
        return field_encryption_service.decrypt_json(report.output_encrypted)
    return report.output_json or {}


def _empty_blocked_output() -> dict:
    return {
        "incident_summary": "Explanation blocked: unsafe input detected.",
        "likely_cause_explanation": "The evidence is limited and human review is required.",
        "supporting_evidence_summary": "No LLM explanation was generated.",
        "alternative_hypotheses": [],
        "missing_evidence_questions": [],
        "recommended_fix_draft": "",
        "fix_verification_checklist": [],
        "human_review_note": "Human review is required. Input failed masked-only guard.",
        "safety_notes": {
            "uses_masked_evidence_only": True,
            "contains_raw_sensitive_values": True,
            "contains_overclaiming": False,
            "human_review_required": True,
        },
    }


def _persist_report(
    db: Session,
    *,
    incident_id: str,
    provider_used: str,
    model_name: str | None,
    context_hash: str,
    output_json: dict,
    safety_status: str,
    validation_errors: list[str] | None,
) -> LlmReport:
    report = LlmReport(
        report_id=generate_report_id(),
        incident_id=incident_id,
        provider_used=provider_used,
        model_name=model_name,
        input_context_hash=context_hash,
        safety_status=safety_status,
        validation_errors=validation_errors,
    )
    if field_encryption_service.encryption_enabled():
        payload = field_encryption_service.encrypt_json(
            value=output_json,
            table="llm_reports",
            record_id=incident_id,
            field="output_json",
            extra=provider_used,
        )
        report.output_encrypted = payload
        report.output_crypto_metadata = {"kid": payload.get("kid")}
        report.is_encrypted = True
        report.output_json = None
    else:
        report.output_json = output_json
        report.is_encrypted = False
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def _log_blocked_input(db: Session, incident_id: str, codes: list[str]) -> None:
    audit_service.log_action(
        db,
        action="explanation_blocked_unsafe_input",
        target_type="incident",
        target_id=incident_id,
        details={"incident_id": incident_id, "violation_codes": codes},
    )
    db.commit()


def list_llm_reports(db: Session, incident_id: str) -> list[LlmReport]:
    stmt = (
        select(LlmReport)
        .where(LlmReport.incident_id == incident_id)
        .order_by(LlmReport.created_at.desc(), LlmReport.id.desc())
    )
    return list(db.scalars(stmt).all())


def explain_incident(
    db: Session,
    incident_id: str,
    *,
    provider: str | None = None,
    model: str | None = None,
    force_template: bool = False,
) -> ExplainResult:
    incident = get_incident(db, incident_id)
    if not incident:
        raise KeyError(f"Incident not found: {incident_id}")

    has_scores = db.scalar(
        select(RootCauseScore.id)
        .where(RootCauseScore.incident_id == incident_id)
        .limit(1)
    )
    if not has_scores:
        raise ValueError(
            "No root-cause scores found; run POST /incidents/analyse before explain"
        )

    context = llm_context_service.build_llm_context(db, incident_id)
    context_hash = llm_context_service.hash_context(context)

    input_guard = llm_safety_service.validate_input_context(context)
    if not input_guard.safe:
        _log_blocked_input(db, incident_id, input_guard.violation_codes)
        output = _empty_blocked_output()
        report = _persist_report(
            db,
            incident_id=incident_id,
            provider_used="blocked",
            model_name=None,
            context_hash=context_hash,
            output_json=output,
            safety_status="blocked_input",
            validation_errors=input_guard.violation_codes,
        )
        return ExplainResult(
            report_id=report.report_id,
            incident_id=incident_id,
            provider_used="blocked",
            model_name=None,
            safety_status="blocked_input",
            validation_errors=input_guard.violation_codes,
            output=output,
            blocked=True,
        )

    settings = get_settings()
    use_template = force_template or provider == "template"
    provider_used = "template"
    model_name: str | None = None
    raw_output: dict

    if use_template:
        raw_output = template_explanation_service.generate_investigation_output(context)
    else:
        chosen = provider or settings.llm_default_provider
        if chosen == "ollama" and llm_provider_service.is_ollama_available():
            try:
                model_name = model or settings.ollama_default_model
                raw_output = llm_provider_service.generate_with_ollama(
                    context,
                    model=model_name,
                    backup_model=settings.ollama_backup_model,
                )
                provider_used = "ollama"
            except llm_provider_service.OllamaUnavailableError:
                raw_output = template_explanation_service.generate_investigation_output(
                    context
                )
                provider_used = "template"
        else:
            raw_output = template_explanation_service.generate_investigation_output(context)
            provider_used = "template"

    validation = llm_safety_service.validate_investigation_output(raw_output, context)
    final_output = validation.sanitized_output or raw_output

    if validation.passed and not validation.flagged:
        safety_status = "passed"
    elif validation.passed and validation.flagged:
        safety_status = "flagged"
    else:
        safety_status = "validation_failed"
        if provider_used == "ollama":
            final_output = template_explanation_service.generate_investigation_output(
                context
            )
            validation = llm_safety_service.validate_investigation_output(
                final_output, context
            )
            provider_used = "template"
            model_name = None
            safety_status = "passed" if validation.passed else "validation_failed"

    report = _persist_report(
        db,
        incident_id=incident_id,
        provider_used=provider_used,
        model_name=model_name,
        context_hash=context_hash,
        output_json=final_output,
        safety_status=safety_status,
        validation_errors=validation.errors,
    )

    return ExplainResult(
        report_id=report.report_id,
        incident_id=incident_id,
        provider_used=provider_used,
        model_name=model_name,
        safety_status=safety_status,
        validation_errors=validation.errors,
        output=final_output,
        blocked=False,
    )
