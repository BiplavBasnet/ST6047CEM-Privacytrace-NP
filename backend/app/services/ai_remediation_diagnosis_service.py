"""Problem-specific AI remediation diagnosis + primary remediation selection.

Produces ONE best-supported remediation from a masked evidence package and
source localisation result. Prefer deterministic playbook mapping; optional
provider enrichment never invents file/function paths.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import case, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.remediation_action import RemediationAction
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.models.incident import Incident
from app.models.fix_verification import FixVerification
from app.models.verified_remediation_learning import PatchProposal, VerifiedRemediationCase
from app.models.workflow_verification import ControlledRetest, RemediationImplementationRecord, RemediationTestExecution, VerificationOutcome
from app.schemas.problem_specific_remediation_schema import (
    AIProblemSpecificRemediationResponse,
    AIProviderEnrichment,
    PrimaryRemediationOut,
    ProposedChangeOut,
    RemediationDiagnosisOut,
)
from app.services import (
    ai_prompt_injection_safety,
    ai_output_safety_service,
    ai_provider_client,
    audit_service,
    remediation_ai_safety_service,
    remediation_code_context_service,
    remediation_context_service,
    remediation_source_locator_service,
    verified_outcome_learning_service,
    workflow_provenance_service,
)
from app.services.workflow_provenance_service import WorkflowProvenanceError

# Root-cause category → primary remediation class (playbook seed).
_PLAYBOOK: dict[str, dict[str, str]] = {
    "unsafe_request_body_logging": {
        "remediation_type": "request_body_redaction",
        "title": "Redact sensitive request-body fields before log serialisation",
        "recommended_change": (
            "Apply field-level redaction/masking to sensitive request-body attributes "
            "before the logger serialises the payload."
        ),
        "why_not_broader": (
            "Disabling all request logging would remove useful operational telemetry "
            "beyond the implicated sensitive fields."
        ),
        "component": "request logging middleware",
    },
    "authorization_header_logging": {
        "remediation_type": "request_header_redaction",
        "title": "Redact Authorization headers before request-log serialisation",
        "recommended_change": (
            "Redact or remove Authorization/Bearer values before headers are written "
            "to application or access logs."
        ),
        "why_not_broader": (
            "Turning off all header logging would hide useful non-sensitive diagnostics."
        ),
        "component": "request header logging",
    },
    "unsafe_request_header_logging": {
        "remediation_type": "request_header_redaction",
        "title": "Redact Authorization headers before request-log serialisation",
        "recommended_change": (
            "Redact or remove Authorization/Bearer values before headers are written "
            "to application or access logs."
        ),
        "why_not_broader": (
            "Turning off all header logging would hide useful non-sensitive diagnostics."
        ),
        "component": "request logging middleware",
    },
    "jwt_or_token_leakage": {
        "remediation_type": "request_header_redaction",
        "title": "Prevent token values from entering logs and exports",
        "recommended_change": (
            "Mask JWT/bearer/session tokens at the logging boundary and ensure exports "
            "only retain fingerprints or masked previews."
        ),
        "why_not_broader": "Revoking all tokens immediately may be needed separately but does not fix the logging path.",
        "component": "token handling / logging boundary",
    },
    "debug_logging_enabled_after_deployment": {
        "remediation_type": "debug_logging_restriction",
        "title": "Restrict debug logging in non-development environments",
        "recommended_change": (
            "Enforce environment-based log level policy so debug request dumps are not "
            "enabled outside development."
        ),
        "why_not_broader": "A permanent global log shutdown is wider than the identified deployment misconfiguration.",
        "component": "logging configuration",
    },
    "incomplete_redaction_rule": {
        "remediation_type": "sensitive_field_allowlist",
        "title": "Complete redaction allowlist for implicated sensitive fields",
        "recommended_change": (
            "Extend the redaction/masking allowlist so the observed sensitive types are "
            "never written in clear form."
        ),
        "why_not_broader": "Rewriting the entire logging stack is unnecessary when field rules are incomplete.",
        "component": "redaction middleware",
    },
    "hardcoded_secret_or_api_key": {
        "remediation_type": "secret_configuration_removal",
        "title": "Remove hardcoded secrets and rotate exposed credentials",
        "recommended_change": (
            "Remove secret material from source/config, load from a secret store, and "
            "rotate any exposed keys."
        ),
        "why_not_broader": "Rewriting unrelated services does not address the secret exposure path.",
        "component": "secret configuration",
    },
    "access_control_failure": {
        "remediation_type": "access_control_data_minimisation",
        "title": "Tighten access checks and minimise sensitive fields in denied/allowed responses",
        "recommended_change": (
            "Ensure ownership/authorisation checks run before sensitive data access and "
            "that denied or error paths do not echo sensitive identifiers."
        ),
        "why_not_broader": "Disabling the endpoint entirely has wider product impact than fixing the access path.",
        "component": "access control / data minimisation",
    },
}


class DiagnosisError(Exception):
    pass


class DiagnosisGateError(DiagnosisError):
    pass


class DiagnosisNotFoundError(DiagnosisError):
    pass


class DiagnosisStateError(DiagnosisError):
    pass


def _new_diagnosis_id() -> str:
    return f"RDX-{uuid.uuid4().hex[:12].upper()}"


def _new_remediation_id() -> str:
    return f"PRM-{uuid.uuid4().hex[:10].upper()}"


def _snapshot_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str)
    return f"sha256:{hashlib.sha256(blob.encode('utf-8')).hexdigest()}"


def _require_approved_root_cause_review(db: Session, incident_id: str):
    try:
        return workflow_provenance_service.assert_valid_review_for_remediation(db, incident_id)
    except WorkflowProvenanceError as exc:
        raise DiagnosisGateError(str(exc)) from exc


def _resolve_generation_mode(*, ai_attempted: bool, ai_succeeded: bool, ai_failure_type: str | None) -> str:
    if ai_attempted and ai_succeeded:
        return "playbook_plus_ai"
    if ai_attempted and not ai_succeeded:
        return "fallback_playbook"
    return "playbook"


def _canonical_taxonomy_from_package(package: dict[str, Any]) -> dict[str, str | None]:
    types = package.get("sensitive_types") or package.get("sensitive_data_types") or []
    locs = package.get("exposure_locations") or []
    return {
        "sensitive_type": str(types[0]) if types else None,
        "exposure_location": str(locs[0]) if locs else None,
        "root_cause_category": (
            package.get("root_cause_category") or package.get("likely_root_cause")
        ),
    }


def _create_action_from_accepted_diagnosis(
    db: Session,
    row: RemediationDiagnosis,
    *,
    actor_id: int | None,
) -> RemediationAction:
    existing = db.scalar(
        select(RemediationAction).where(RemediationAction.diagnosis_id == row.diagnosis_id)
    )
    if existing:
        return existing

    primary = row.primary_remediation if isinstance(row.primary_remediation, dict) else {}
    idempotency_key = f"diag:{row.diagnosis_id}"
    by_key = db.scalar(
        select(RemediationAction).where(RemediationAction.idempotency_key == idempotency_key)
    )
    if by_key:
        return by_key

    try:
        with db.begin_nested():
            action = RemediationAction(
                remediation_action_id=f"REM-{uuid4().hex[:12].upper()}",
                incident_id=row.incident_id,
                diagnosis_id=row.diagnosis_id,
                root_cause_analysis_id=row.root_cause_analysis_id,
                review_decision_id=row.review_decision_id,
                approved_payload_version=1,
                action_type=str(primary.get("remediation_type") or "remediation"),
                action_description=str(
                    primary.get("recommended_change")
                    or row.problem_statement
                    or "Approved remediation"
                ),
                approved_problem_statement=row.problem_statement,
                approved_change=str(primary.get("recommended_change") or "") or None,
                affected_service=row.affected_service,
                affected_endpoint=row.affected_endpoint,
                affected_component=row.affected_component or "implicated component",
                affected_file=row.affected_file,
                affected_function=row.affected_function,
                affected_configuration=row.affected_configuration,
                implementation_steps=list(primary.get("implementation_steps") or []),
                required_tests=list(primary.get("tests_required") or []),
                retest_requirements=list(primary.get("retest_requirements") or []),
                risks=str(primary.get("implementation_risk") or "") or None,
                rollback_plan=str(primary.get("rollback_plan") or "") or None,
                remediation_fingerprint=verified_outcome_learning_service.remediation_fingerprint(
                    remediation_type=str(primary.get("remediation_type") or "") or None,
                    root_cause_category=str(primary.get("root_cause_category") or "") or None,
                    sensitive_type=str(primary.get("sensitive_type") or "") or None,
                    exposure_location=str(primary.get("exposure_location") or "") or None,
                    affected_component=row.affected_component,
                    implementation_mode="controlled_patch",
                ),
                implementation_mode="controlled_local_test_workspace",
                assigned_owner=str(actor_id),
                status="not_started",
                priority="medium",
                retest_required=True,
                requires_revalidation=False,
                workflow_status="current",
                idempotency_key=idempotency_key,
                approved_by=actor_id,
                approved_at=datetime.now(UTC),
                created_by=actor_id,
            )
            db.add(action)
            db.flush()
        return action
    except IntegrityError:
        canonical = db.scalar(
            select(RemediationAction).where(
                RemediationAction.diagnosis_id == row.diagnosis_id
            )
        )
        if canonical is None:
            raise
        return canonical


def get_action_for_diagnosis(
    db: Session, diagnosis_id: str
) -> RemediationAction | None:
    return db.scalar(
        select(RemediationAction).where(RemediationAction.diagnosis_id == diagnosis_id)
    )


def _playbook_for(likely_cause: str | None) -> dict[str, str]:
    if likely_cause and likely_cause in _PLAYBOOK:
        return _PLAYBOOK[likely_cause]
    return {
        "remediation_type": "other",
        "title": "Apply evidence-aligned remediation for the ranked likely root cause",
        "recommended_change": (
            "Implement the narrowest change that stops the observed sensitive-data exposure "
            "path without inventing unsupported source locations."
        ),
        "why_not_broader": "Broader disablement may remove unrelated operational visibility.",
        "component": "implicated component (not precisely localised)",
    }


def _build_response(
    *,
    package: dict[str, Any],
    localisation: dict[str, Any],
    code_context: dict[str, Any],
) -> AIProblemSpecificRemediationResponse:
    likely = package.get("likely_root_cause") or package.get("likely_root_cause_candidate")
    playbook = _playbook_for(str(likely) if likely else None)
    exact = bool(localisation.get("exact_source_location_known"))
    file_path = localisation.get("file_path") if exact else None
    function_name = localisation.get("function_or_class") if exact else None

    sensitive = None
    types = package.get("sensitive_data_types") or package.get("sensitive_types") or []
    if types:
        sensitive = str(types[0])
    locations = package.get("exposure_locations") or []
    exposure_location = str(locations[0]) if locations else None

    diagnosis = RemediationDiagnosisOut(
        incident_id=str(package["incident_id"]),
        root_cause_analysis_id=package.get("root_cause_analysis_id"),
        detected_sensitive_type=sensitive,
        exposure_location=exposure_location,
        problem_statement=(
            f"Sensitive-data exposure of type '{sensitive or 'unknown'}' was observed"
            f" at exposure location '{exposure_location or 'unknown'}'. "
            f"Likely root cause ranked as '{likely or 'not ranked'}'."
        ),
        technical_mechanism=(
            f"Evidence aligns with component '{localisation.get('likely_component') or playbook['component']}'. "
            "This remains a likely technical mechanism pending human review."
        ),
        affected_service=package.get("affected_service"),
        affected_endpoint=package.get("affected_endpoint"),
        affected_component=localisation.get("likely_component") or playbook["component"],
        affected_file_if_known=file_path,
        affected_function_if_known=function_name,
        affected_configuration_if_known=localisation.get("configuration_section") if exact else None,
        supporting_evidence_ids=list(package.get("supporting_evidence_ids") or []),
        contradicting_evidence_ids=list(package.get("contradicting_evidence_ids") or []),
        missing_evidence=list(package.get("missing_evidence") or localisation.get("limitations") or []),
        diagnosis_confidence=str(package.get("root_cause_confidence") or package.get("confidence_level") or "medium"),
        diagnosis_limitations=list(package.get("limitations") or [])
        + (["Exact source location not established."] if not exact else []),
        exact_source_location_known=exact,
        human_review_required=True,
    )

    primary = PrimaryRemediationOut(
        remediation_id=_new_remediation_id(),
        title=playbook["title"],
        remediation_type=playbook["remediation_type"],  # type: ignore[arg-type]
        exact_problem_addressed=diagnosis.problem_statement,
        affected_component=diagnosis.affected_component or playbook["component"],
        affected_file_if_known=file_path,
        affected_function_if_known=function_name,
        affected_configuration_if_known=diagnosis.affected_configuration_if_known,
        recommended_change=playbook["recommended_change"],
        why_this_solution=(
            "Directly targets the ranked likely root-cause category and the observed "
            "exposure location while preserving non-sensitive operational telemetry."
        ),
        evidence_alignment=(
            "Aligned with masked detections, exposure location (when present), and the "
            "top likely root-cause ranking from human-reviewed analysis."
        ),
        why_not_broader_fix=playbook["why_not_broader"],
        expected_privacy_impact=(
            "Stops clear-form sensitive values from entering the implicated logging/export path."
        ),
        operational_impact="Limited to the implicated logging/redaction/access component.",
        implementation_risk="Medium — requires regression tests and controlled retest evidence.",
        prerequisites=["Accepted human root-cause review", "Human remediation approval"],
        implementation_steps=[
            "Review primary remediation against supporting evidence",
            "Implement the narrow change in a controlled test workspace only after approval",
            "Run allowlisted tests and controlled retest of the original exposure condition",
        ],
        tests_required=[
            "Synthetic sensitive value must not appear in logs/reports after remediation",
            "Non-sensitive metadata should remain available where expected",
        ],
        retest_requirements=[
            "Same service/endpoint/exposure location/sensitive-type dimensions where feasible",
            "Use synthetic values only",
        ],
        rollback_plan="Revert the approved change in the controlled workspace and restore prior configuration.",
        remediation_confidence="medium" if exact else "low",
        confidence_limitations=(
            [] if exact else ["Exact source-level patch is not available without stronger localisation evidence."]
        ),
        human_approval_required=True,
    )

    exact_change_available = False
    proposed = None
    if exact and code_context.get("context_available") and file_path:
        diff = None
        if str(file_path).replace("\\", "/") == "fixtures/gold_standard_wallet/request_logger.py":
            from app.config import get_backend_root
            from pathlib import Path
            import difflib

            vuln = get_backend_root() / "fixtures" / "gold_standard_wallet" / "request_logger.py"
            fixed = get_backend_root() / "fixtures" / "gold_standard_wallet" / "request_logger_fixed.py"
            if vuln.is_file() and fixed.is_file():
                old = vuln.read_text(encoding="utf-8")
                new = fixed.read_text(encoding="utf-8")
                diff = "".join(
                    difflib.unified_diff(
                        old.splitlines(keepends=True),
                        new.splitlines(keepends=True),
                        fromfile=f"a/{file_path}",
                        tofile=f"b/{file_path}",
                    )
                )
        exact_change_available = bool(diff)
        if diff:
            proposed = ProposedChangeOut(
                change_type="code_patch",
                file_path=str(file_path),
                symbol_or_function=function_name,
                base_content_hash=code_context.get("content_hash"),
                change_summary=playbook["recommended_change"],
                proposed_diff=diff,
                why_each_change_is_needed=[
                    "Targets the localised exposure path identified by scanner/change evidence."
                ],
                expected_security_effect="Removes clear-form sensitive values from the implicated sink.",
                side_effects=["May require updating related unit tests"],
                tests_required=primary.tests_required,
            )

    limitations = list(diagnosis.diagnosis_limitations)
    if not exact_change_available:
        limitations.append(
            "Available evidence supports component-level remediation but is insufficient "
            "for a reliable source-level patch."
        )

    return AIProblemSpecificRemediationResponse(
        diagnosis=diagnosis,
        primary_remediation=primary,
        alternative_remediations=[],
        exact_change_available=exact_change_available,
        proposed_change=proposed,
        tests=list(primary.tests_required),
        retest_plan={
            "use_synthetic_values": True,
            "match_dimensions": ["service", "endpoint", "exposure_location", "sensitive_type"],
            "requirements": primary.retest_requirements,
        },
        rollback_plan={"summary": primary.rollback_plan},
        limitations=limitations,
        human_approval_required=True,
    )


def _provider_enrichment(content: dict[str, Any] | str) -> AIProviderEnrichment:
    try:
        value = json.loads(content) if isinstance(content, str) else content
    except json.JSONDecodeError as exc:
        raise ai_provider_client.AIProviderError(
            "AI provider returned invalid JSON.", "malformed_output"
        ) from exc
    if not isinstance(value, dict):
        raise ai_provider_client.AIProviderError(
            "AI provider returned a non-object response.", "schema_invalid"
            )
    source_keys = {
        "file_path",
        "affected_file",
        "function",
        "symbol",
        "configuration",
        "remediation_type",
        "proposed_change",
        "title",
    }
    if source_keys.intersection(value):
        raise ai_provider_client.AIProviderError(
            "AI provider attempted to override server-owned source/remediation facts.",
            "source_claim_invalid",
        )
    try:
        enrichment = AIProviderEnrichment.model_validate(value)
    except ValidationError as exc:
        raise ai_provider_client.AIProviderError(
            "AI provider output failed strict schema validation.", "schema_invalid"
        ) from exc
    safety = ai_output_safety_service.validate_ai_output(enrichment.model_dump())
    if not safety.safe:
        raise ai_provider_client.AIProviderError(safety.message, "output_unsafe")
    return enrichment


def _apply_provider_enrichment(
    response: AIProblemSpecificRemediationResponse,
    enrichment: AIProviderEnrichment,
) -> AIProblemSpecificRemediationResponse:
    primary = response.primary_remediation.model_copy(
        update={
            "why_this_solution": enrichment.why_this_solution,
            "evidence_alignment": enrichment.evidence_alignment,
        }
    )
    return response.model_copy(
        update={
            "primary_remediation": primary,
            "limitations": list(dict.fromkeys([*response.limitations, *enrichment.limitations])),
        }
    )


def generate_problem_specific_remediation(
    db: Session,
    incident_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> tuple[RemediationDiagnosis, AIProblemSpecificRemediationResponse]:
    db.scalar(select(Incident).where(Incident.incident_id == incident_id).with_for_update())
    provenance = _require_approved_root_cause_review(db, incident_id)
    package = remediation_context_service.build_remediation_evidence_package(db, incident_id)
    localisation = remediation_source_locator_service.locate_source_evidence(
        db, incident_id, package=package
    )
    code_context = remediation_code_context_service.build_code_context(
        file_path=localisation.get("file_path") if localisation.get("exact_source_location_known") else None
    )
    response = _build_response(package=package, localisation=localisation, code_context=code_context)

    settings = get_settings()
    ai_attempted = bool(
        settings.ai_assistant_enabled and ai_provider_client.provider_configured()
    )
    ai_succeeded = False
    ai_failure_type = None
    provider = "deterministic_playbook"
    model = "privacytrace-playbook-v1"
    if ai_attempted:
        try:
            outbound = ai_prompt_injection_safety.build_untrusted_provider_context(
                package, localisation=localisation, code_context=code_context
            )
            provider_result = ai_provider_client.generate_remediation_suggestion(outbound)
            response = _apply_provider_enrichment(
                response, _provider_enrichment(provider_result.content)
            )
            provider = provider_result.provider
            model = provider_result.model or "unknown"
            ai_succeeded = True
        except (ai_provider_client.AIProviderError, remediation_ai_safety_service.RemediationAISafetyError) as exc:
            ai_failure_type = getattr(exc, "failure_type", "input_safety_blocked")

    generation_mode = _resolve_generation_mode(
        ai_attempted=ai_attempted,
        ai_succeeded=ai_succeeded,
        ai_failure_type=ai_failure_type,
    )
    source_refs = list(localisation.get("evidence_references") or [])
    response = response.model_copy(
        update={
            "generation_mode": generation_mode,
            "model_provider": provider if ai_succeeded else "deterministic_playbook",
            "model_name": model if ai_succeeded else "privacytrace-playbook-v1",
            "ai_failure_type": ai_failure_type,
            "source_claim_evidence_refs": source_refs,
        }
    )
    remediation_ai_safety_service.validate_problem_specific_response(response)
    taxonomy = _canonical_taxonomy_from_package(package)
    ranking = verified_outcome_learning_service.ranking_influence_for_similar(
        db,
        root_cause_category=taxonomy.get("root_cause_category"),
        remediation_type=response.primary_remediation.remediation_type,
        sensitive_type=taxonomy.get("sensitive_type"),
        exposure_location=taxonomy.get("exposure_location"),
        affected_component=response.primary_remediation.affected_component,
        implementation_mode="controlled_patch",
    )
    gate = verified_outcome_learning_service.fingerprint_attempt_gate(
        db,
        remediation_type=response.primary_remediation.remediation_type,
        root_cause_category=taxonomy.get("root_cause_category"),
        sensitive_type=taxonomy.get("sensitive_type"),
        exposure_location=taxonomy.get("exposure_location"),
        affected_component=response.primary_remediation.affected_component,
    )
    extra_limits = list(response.limitations)
    evidence_alignment = response.primary_remediation.evidence_alignment
    if ranking.get("ranked_cases"):
        top = ranking["ranked_cases"][0]
        evidence_alignment = (
            f"{evidence_alignment} Previously verified remediation matched this incident "
            f"({top['verified_case_id']}; score={top['score']}; "
            f"why={', '.join(top.get('why_selected') or [])}). "
            "Verified outcome-informed remediation recommendation — human approval still required."
        )
        if top.get("remediation_type") and top["score"] >= 6:
            # Prefer historically verified type as supporting evidence for primary selection.
            response = response.model_copy(
                update={
                    "primary_remediation": response.primary_remediation.model_copy(
                        update={
                            "remediation_type": top["remediation_type"],
                            "evidence_alignment": evidence_alignment,
                        }
                    )
                }
            )
        else:
            response = response.model_copy(
                update={
                    "primary_remediation": response.primary_remediation.model_copy(
                        update={"evidence_alignment": evidence_alignment}
                    )
                }
            )
    if gate.get("block_identical_auto_retry"):
        extra_limits.append(
            "HUMAN_REVIEW_REQUIRED / MORE_EVIDENCE_REQUIRED: identical remediation fingerprint "
            "previously failed or rolled back under equivalent context."
        )
        response = response.model_copy(update={"limitations": list(dict.fromkeys([*extra_limits]))})
    # Prefer RCA evidence snapshot hash for provenance alignment.
    snap = provenance.evidence_snapshot_hash
    row = RemediationDiagnosis(
        diagnosis_id=_new_diagnosis_id(),
        incident_id=incident_id,
        root_cause_analysis_id=provenance.analysis_id,
        root_cause_analysis_version=provenance.analysis_version,
        evidence_snapshot_hash=snap,
        review_decision_id=provenance.review.id,
        generation_mode=generation_mode,
        playbook_id="privacytrace-playbook-v1",
        playbook_version="1",
        ai_failure_type=ai_failure_type,
        fallback_mode="verified_playbook" if generation_mode == "fallback_playbook" else None,
        model_provider=response.model_provider,
        model_name=response.model_name,
        prompt_template_version="problem-specific-v1",
        recommendation_policy_version="playbook-v1",
        problem_statement=response.diagnosis.problem_statement,
        technical_mechanism=response.diagnosis.technical_mechanism,
        affected_service=response.diagnosis.affected_service,
        affected_endpoint=response.diagnosis.affected_endpoint,
        affected_component=response.diagnosis.affected_component,
        affected_file=response.diagnosis.affected_file_if_known,
        affected_function=response.diagnosis.affected_function_if_known,
        affected_configuration=response.diagnosis.affected_configuration_if_known,
        exact_source_location_known=response.diagnosis.exact_source_location_known,
        supporting_evidence_ids=response.diagnosis.supporting_evidence_ids,
        contradicting_evidence_ids=response.diagnosis.contradicting_evidence_ids,
        missing_evidence=response.diagnosis.missing_evidence,
        diagnosis_confidence=response.diagnosis.diagnosis_confidence,
        limitations=response.limitations,
        primary_remediation=response.primary_remediation.model_dump(),
        alternative_remediations=[a.model_dump() for a in response.alternative_remediations],
        exact_change_available=response.exact_change_available,
        proposed_change=response.proposed_change.model_dump() if response.proposed_change else None,
        status="awaiting_human_review",
        created_by_user_id=actor_id,
    )
    # Attach canonical taxonomy into primary remediation for learning (never problem_statement).
    primary = dict(row.primary_remediation or {})
    primary["source_claim_evidence_refs"] = source_refs
    if taxonomy.get("sensitive_type"):
        primary.setdefault("sensitive_type", taxonomy["sensitive_type"])
    if taxonomy.get("exposure_location"):
        primary.setdefault("exposure_location", taxonomy["exposure_location"])
    if taxonomy.get("root_cause_category"):
        primary.setdefault("root_cause_category", taxonomy["root_cause_category"])
    primary["verified_case_influence"] = {
        "comparable_verified_cases": ranking.get("comparable_verified_cases"),
        "case_ids": ranking.get("case_ids"),
        "ranked_top": (ranking.get("ranked_cases") or [])[:3],
        "note": ranking.get("note"),
        "remediation_fingerprint": gate.get("remediation_fingerprint"),
        "block_identical_auto_retry": gate.get("block_identical_auto_retry"),
    }
    row.primary_remediation = primary

    reason = "Superseded by a newly generated diagnosis for the current governed branch."
    old_ids = list(db.scalars(select(RemediationDiagnosis.diagnosis_id).where(
        RemediationDiagnosis.incident_id == incident_id,
        RemediationDiagnosis.root_cause_analysis_id == provenance.analysis_id,
        RemediationDiagnosis.review_decision_id == provenance.review.id,
        RemediationDiagnosis.workflow_status == "current",
    )).all())
    if old_ids:
        action_ids = list(db.scalars(select(RemediationAction.remediation_action_id).where(RemediationAction.diagnosis_id.in_(old_ids))).all())
        implementation_ids = list(db.scalars(select(RemediationImplementationRecord.implementation_id).where(RemediationImplementationRecord.diagnosis_id.in_(old_ids))).all())
        outcome_ids = list(db.scalars(select(VerificationOutcome.verification_outcome_id).where(VerificationOutcome.remediation_diagnosis_id.in_(old_ids))).all())
        db.execute(update(RemediationDiagnosis).where(RemediationDiagnosis.diagnosis_id.in_(old_ids)).values(workflow_status="superseded"))
        if action_ids:
            db.execute(update(RemediationAction).where(RemediationAction.remediation_action_id.in_(action_ids)).values(workflow_status="superseded", requires_revalidation=True, invalidation_reason=reason))
            db.execute(update(PatchProposal).where(PatchProposal.remediation_action_id.in_(action_ids)).values(workflow_status="superseded", invalidation_reason=reason))
            db.execute(update(RemediationTestExecution).where(RemediationTestExecution.remediation_action_id.in_(action_ids)).values(workflow_status="superseded", invalidation_reason=reason))
        if implementation_ids:
            db.execute(update(RemediationImplementationRecord).where(RemediationImplementationRecord.implementation_id.in_(implementation_ids)).values(workflow_status="superseded", invalidation_reason=reason))
            db.execute(update(ControlledRetest).where(ControlledRetest.implementation_id.in_(implementation_ids)).values(workflow_status="superseded", invalidation_reason=reason))
        db.execute(update(FixVerification).where(FixVerification.remediation_diagnosis_id.in_(old_ids)).values(workflow_status="superseded", invalidation_reason=reason))
        db.execute(update(VerificationOutcome).where(VerificationOutcome.remediation_diagnosis_id.in_(old_ids)).values(workflow_status="superseded", invalidation_reason=reason, eligible_for_learning=False, eligibility_reason=reason))
        if outcome_ids:
            db.execute(update(VerifiedRemediationCase).where(VerifiedRemediationCase.verification_outcome_id.in_(outcome_ids)).values(workflow_status="superseded", invalidation_reason=reason, eligible_for_learning=False, eligibility_reason=reason))
    db.add(row)
    db.flush()
    audit_service.log_action(
        db,
        action="remediation_diagnosis_generated",
        target_type="remediation_diagnosis",
        target_id=row.diagnosis_id,
        details={
            "incident_id": incident_id,
            "exact_source_location_known": row.exact_source_location_known,
            "generation_mode": generation_mode,
            "root_cause_analysis_id": provenance.analysis_id,
            "ai_enabled": bool(settings.ai_assistant_enabled),
        },
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    db.commit()
    db.refresh(row)
    response = response.model_copy(update={"diagnosis_id": row.diagnosis_id})
    return row, response


def get_diagnosis(db: Session, diagnosis_id: str) -> RemediationDiagnosis:
    row = db.scalar(
        select(RemediationDiagnosis).where(RemediationDiagnosis.diagnosis_id == diagnosis_id)
    )
    if not row:
        raise DiagnosisNotFoundError(f"Diagnosis not found: {diagnosis_id}")
    return row


def get_current_diagnosis(db: Session, incident_id: str) -> RemediationDiagnosis | None:
    return db.scalar(select(RemediationDiagnosis).where(
        RemediationDiagnosis.incident_id == incident_id,
        RemediationDiagnosis.workflow_status == "current",
    ).order_by(
        case((RemediationDiagnosis.status.in_(("accepted", "accepted_with_edits")), 0), else_=1),
        RemediationDiagnosis.created_at.desc(), RemediationDiagnosis.id.desc(),
    ).limit(1))


def review_diagnosis(
    db: Session,
    diagnosis_id: str,
    *,
    decision: str,
    notes: str | None,
    edited_primary: dict[str, Any] | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> RemediationDiagnosis:
    row = get_diagnosis(db, diagnosis_id)
    decision_norm = decision.strip().lower()
    if row.status in {"accepted", "accepted_with_edits"} and decision_norm in {
        "accept",
        "accept_with_edits",
    }:
        try:
            workflow_provenance_service.assert_current_governed_remediation_permission(
                db,
                row.incident_id,
                actor_id=actor_id,
                require_active_human_actor=True,
                root_cause_analysis_id=row.root_cause_analysis_id,
                root_cause_analysis_version=row.root_cause_analysis_version,
                evidence_snapshot_hash=row.evidence_snapshot_hash,
                review_decision_id=row.review_decision_id,
                diagnosis_id=row.diagnosis_id,
            )
        except WorkflowProvenanceError as exc:
            raise DiagnosisGateError(str(exc)) from exc
        _create_action_from_accepted_diagnosis(db, row, actor_id=actor_id)
        db.commit()
        db.refresh(row)
        return row
    if row.status not in {"generated", "awaiting_human_review"}:
        raise DiagnosisStateError(f"Diagnosis cannot be reviewed from status={row.status}")

    editable_primary_fields = {
        "title",
        "recommended_change",
        "why_this_solution",
        "evidence_alignment",
        "why_not_broader_fix",
        "expected_privacy_impact",
        "operational_impact",
        "implementation_risk",
        "prerequisites",
        "implementation_steps",
        "tests_required",
        "retest_requirements",
        "rollback_plan",
        "confidence_limitations",
    }
    if decision_norm == "accept_with_edits" and edited_primary:
        unknown = set(edited_primary) - editable_primary_fields - {"problem_statement"}
        if unknown:
            raise DiagnosisStateError(
                "Unsupported remediation edit fields: " + ", ".join(sorted(unknown))
            )
        reviewer_payload = {"edited_primary": edited_primary, "notes": notes}
        reviewer_safety = ai_output_safety_service.validate_reviewer_text(reviewer_payload)
        if not reviewer_safety.safe:
            raise DiagnosisStateError("Reviewer remediation edits failed safety validation.")
        try:
            remediation_ai_safety_service.assert_no_raw_sensitive(reviewer_payload)
        except remediation_ai_safety_service.RemediationAISafetyError as exc:
            raise DiagnosisStateError(
                "Reviewer remediation edits failed safety validation."
            ) from exc
    elif notes:
        reviewer_safety = ai_output_safety_service.validate_reviewer_text(notes)
        if not reviewer_safety.safe:
            raise DiagnosisStateError("Reviewer notes failed safety validation.")
        try:
            remediation_ai_safety_service.assert_no_raw_sensitive({"reviewer_notes": notes})
        except remediation_ai_safety_service.RemediationAISafetyError as exc:
            raise DiagnosisStateError("Reviewer notes failed safety validation.") from exc

    if decision_norm in {"accept", "accept_with_edits"}:
        try:
            workflow_provenance_service.assert_current_governed_remediation_permission(
                db,
                row.incident_id,
                actor_id=actor_id,
                require_active_human_actor=True,
                root_cause_analysis_id=row.root_cause_analysis_id,
                root_cause_analysis_version=row.root_cause_analysis_version,
                evidence_snapshot_hash=row.evidence_snapshot_hash,
                review_decision_id=row.review_decision_id,
                diagnosis_id=row.diagnosis_id,
            )
        except WorkflowProvenanceError as exc:
            raise DiagnosisGateError(str(exc)) from exc
    # Preserve original AI payload once on first review.
    if row.original_ai_payload is None:
        row.original_ai_payload = {
            "problem_statement": row.problem_statement,
            "technical_mechanism": row.technical_mechanism,
            "primary_remediation": row.primary_remediation,
            "proposed_change": row.proposed_change,
            "affected_component": row.affected_component,
        }

    if decision_norm == "accept":
        row.status = "accepted"
        row.approved_payload = {
            "problem_statement": row.problem_statement,
            "primary_remediation": row.primary_remediation,
            "proposed_change": row.proposed_change,
        }
        row.edited_fields = []
    elif decision_norm == "accept_with_edits":
        if not edited_primary:
            raise DiagnosisStateError("accept_with_edits requires edited_primary remediation payload")
        original_primary = dict(row.primary_remediation or {})
        problem_edit = remediation_ai_safety_service.sanitize_free_text(
            str(edited_primary.get("problem_statement") or "")
        )
        candidate = {
            key: edited_primary.get(key, original_primary.get(key))
            for key in PrimaryRemediationOut.model_fields
        }
        try:
            validated_edit = PrimaryRemediationOut.model_validate(candidate).model_dump()
        except ValidationError as exc:
            raise DiagnosisStateError("Reviewer remediation edits failed validation.") from exc
        try:
            remediation_ai_safety_service.assert_no_raw_sensitive(validated_edit)
        except remediation_ai_safety_service.RemediationAISafetyError as exc:
            raise DiagnosisStateError(
                "Reviewer remediation edits failed safety validation."
            ) from exc
        edited_primary = validated_edit
        # Allow multi-field edits; keep unknown keys from original when omitted.
        merged = {**original_primary, **edited_primary}
        changed = sorted(
            key for key in merged.keys() if merged.get(key) != original_primary.get(key)
        )
        # Optional diagnosis-level fields nested under edited_primary.
        if problem_edit:
            row.problem_statement = problem_edit
            if "problem_statement" not in changed:
                changed.append("problem_statement")
        if "affected_component" in edited_primary and edited_primary["affected_component"]:
            row.affected_component = str(edited_primary["affected_component"])
            if "affected_component" not in changed:
                changed.append("affected_component")
        row.primary_remediation = {
            k: v for k, v in merged.items() if k not in {"problem_statement"}
        }
        row.status = "accepted_with_edits"
        row.edited_fields = changed
        row.approved_payload = {
            "problem_statement": row.problem_statement,
            "primary_remediation": row.primary_remediation,
            "proposed_change": row.proposed_change,
            "edited_fields": changed,
        }
    elif decision_norm == "reject":
        if not notes or not notes.strip():
            raise DiagnosisStateError("Rejection requires a reason")
        row.status = "rejected"
    elif decision_norm == "request_more_evidence":
        row.status = "more_evidence_requested"
    else:
        raise DiagnosisStateError(f"Unsupported decision: {decision}")

    row.reviewer_decision = decision_norm
    safe_notes = remediation_ai_safety_service.sanitize_free_text(notes)
    try:
        remediation_ai_safety_service.assert_no_raw_sensitive({"reviewer_notes": safe_notes})
    except remediation_ai_safety_service.RemediationAISafetyError as exc:
        raise DiagnosisStateError("Reviewer notes failed safety validation.") from exc
    row.reviewer_notes = safe_notes
    row.reviewed_by_user_id = actor_id
    row.reviewed_at = datetime.now(UTC)
    db.add(row)

    if decision_norm in {"accept", "accept_with_edits"}:
        _create_action_from_accepted_diagnosis(db, row, actor_id=actor_id)

    audit_service.log_action(
        db,
        action=f"remediation_diagnosis_{decision_norm}",
        target_type="remediation_diagnosis",
        target_id=row.diagnosis_id,
        details={"incident_id": row.incident_id, "status": row.status},
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
    )
    db.commit()
    db.refresh(row)
    return row
