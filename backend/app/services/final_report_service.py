"""Phase 12.1 — assemble privacy-safe final investigation reports from existing data."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    AIRemediationSuggestion,
    AuditLog,
    Detection,
    EvidenceFile,
    FixVerification,
    Incident,
    LlmReport,
    NormalizedEvent,
    PatchProposal,
    PrivacyAlert,
    RemediationAction,
    RemediationDiagnosis,
    RemediationTestExecution,
    Report,
    ReviewDecision,
    RollbackExecution,
    RootCauseScore,
    ScannerEvidenceRecord,
    User,
    VerificationOutcome,
    VerifiedRemediationCase,
)
from app.models.enums import EvidenceType
from app.schemas.final_report_schema import (
    FinalInvestigationReport,
    FinalReportAuditEntry,
    FinalReportDetection,
    FinalReportEvidenceItem,
    FinalReportExecutiveSummary,
    FinalReportFixVerification,
    FinalReportGuardedExplanation,
    FinalReportHumanReview,
    FinalReportIncidentSection,
    FinalReportLiveAlertItem,
    FinalReportLiveMonitorSummary,
    FinalReportMetadata,
    FinalReportNormalizedEvent,
    FinalReportRootCauseItem,
    FinalReportScannerEvidence,
)
from app.services import (
    audit_service,
    causality_engine,
    field_encryption_service,
    report_readiness_service,
    report_safety_service,
    root_cause_analysis_service,
    root_cause_evidence_strength_service,
    workflow_provenance_service,
)
from app.services.report_service import IncidentNotFoundError

EVIDENCE_ROLE_LABELS: dict[EvidenceType, str] = {
    EvidenceType.API_LOG: "API log evidence",
    EvidenceType.RUNTIME_LOG: "Runtime log evidence",
    EvidenceType.SEMGREP_REPORT: "Static code evidence",
    EvidenceType.GITLEAKS_REPORT: "Secret scanner evidence",
    EvidenceType.TRIVY_REPORT: "Dependency evidence",
    EvidenceType.DEPLOYMENT_LOG: "Deployment evidence",
    EvidenceType.ACCESS_EVENT: "Access-control evidence",
    EvidenceType.SIEM_ALERT: "SIEM alert evidence",
    EvidenceType.SCANNER_BRIDGE_IMPORT: "External scanner evidence import",
    EvidenceType.FIXED_LOG: "Retest log evidence",
    EvidenceType.FIXED_SCAN: "Retest scan evidence",
}

PRIVACY_CONTROLS = [
    "Raw sensitive values are excluded from all export formats.",
    "Only masked credential values are included where applicable.",
    "Raw scanner payloads and raw log content are not returned.",
    "Human review is required before incident closure.",
    "The system does not assign blame or legal responsibility.",
    "Automatic incident closure is not performed.",
    "Audit trail entries use sanitized details only.",
]

LIMITATIONS = [
    "Likely-cause ranking depends on the evidence available at generation time.",
    "Missing evidence reduces confidence and may change rankings after new data arrives.",
    "PrivacyTrace-NP supports investigation; it does not assign blame.",
    "The system does not prove legal responsibility or regulatory compliance.",
    "Professional security judgement is still required.",
    "Thesis and demo environments may use synthetic or sanitised sample data.",
]

ROOT_CAUSE_NOTE = (
    "Root-cause ranking is based on available evidence and should be reviewed by a human analyst."
)

SCANNER_NOTE = (
    "ScannerBridge-NP evidence is supporting evidence only. It does not prove the incident cause."
)

CONFIDENTIALITY_NOTE = (
    "This report contains privacy-preserving incident investigation evidence. "
    "Raw sensitive values have been masked or excluded."
)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _evidence_role(evidence_type: EvidenceType) -> str:
    return EVIDENCE_ROLE_LABELS.get(evidence_type, "Investigation evidence")


SYMPTOM_EVIDENCE_TYPES = {
    EvidenceType.API_LOG.value,
    EvidenceType.RUNTIME_LOG.value,
    EvidenceType.ACCESS_EVENT.value,
    EvidenceType.SIEM_ALERT.value,
}
TECHNICAL_EVIDENCE_TYPES = {
    EvidenceType.DEPLOYMENT_LOG.value,
    EvidenceType.SEMGREP_REPORT.value,
    EvidenceType.GITLEAKS_REPORT.value,
    EvidenceType.TRIVY_REPORT.value,
    EvidenceType.SCANNER_BRIDGE_IMPORT.value,
}
RETEST_EVIDENCE_TYPES = {
    EvidenceType.FIXED_LOG.value,
    EvidenceType.FIXED_SCAN.value,
}


def derive_evidence_strength(
    evidence_types: list[EvidenceType | str],
    *,
    has_live_alert: bool = False,
    has_fix_verification: bool = False,
) -> tuple[str, list[str]]:
    normalized = {
        item.value if isinstance(item, EvidenceType) else str(item).lower()
        for item in evidence_types
    }
    has_symptom = has_live_alert or bool(normalized & SYMPTOM_EVIDENCE_TYPES)
    has_technical = bool(normalized & TECHNICAL_EVIDENCE_TYPES)
    has_retest = has_fix_verification or bool(normalized & RETEST_EVIDENCE_TYPES)

    if has_symptom and has_technical and has_retest:
        level = "very strong"
    elif has_symptom and has_technical:
        level = "strong"
    elif has_technical:
        level = "medium"
    else:
        level = "weak"

    missing: list[str] = []
    if not has_symptom:
        missing.append("API/SIEM log or live alert symptom evidence")
    if not has_technical:
        missing.append("CI/CD deployment, code/config or scanner evidence")
    if not has_retest:
        missing.append("retest evidence after remediation")
    return level, missing


def _derive_recommendations(
    incident: Incident,
    top_cause: str | None,
    has_scanner: bool,
    has_verification: bool,
) -> list[str]:
    recs: list[str] = []
    blob = " ".join(
        filter(
            None,
            [
                incident.summary or "",
                top_cause or "",
                incident.affected_endpoint or "",
            ],
        )
    ).lower()

    if any(k in blob for k in ("log", "logging", "debug", "body")):
        recs.append("Disable or restrict request-body logging on sensitive endpoints.")
        recs.append("Enforce log redaction middleware before logs leave the service boundary.")
        recs.append("Reduce DEBUG-level logging in production environments.")

    if any(k in blob for k in ("secret", "token", "key", "credential", "api_key")):
        recs.append("Review API key and token handling, rotation, and storage practices.")
        recs.append("Add secure logging tests to CI to catch accidental secret exposure.")

    if has_scanner:
        recs.append(
            "Review external scanner supporting evidence alongside primary incident evidence."
        )

    if not has_verification:
        recs.append("Verify remediation using retest evidence and fix verification workflows.")
    else:
        recs.append("Confirm fix verification outcomes with operational stakeholders.")

    recs.append("Monitor for repeated exposure patterns on the affected service and endpoint.")

    return list(dict.fromkeys(recs))[:8]


def _lifecycle_ids(db: Session, incident_id: str) -> dict[str, Any]:
    """Resolve one exact current chain and the next persisted report version."""

    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:incident_id, 0))"),
            {"incident_id": f"report:{incident_id}"},
        )
    prior = db.scalar(select(func.max(Report.report_version)).where(Report.incident_id == incident_id)) or 0
    chain = workflow_provenance_service.get_exact_report_chain(db, incident_id)
    analysis = chain["analysis"]
    review = chain["review"]
    diagnosis = chain["diagnosis"]
    action = chain["action"]
    implementation = chain["implementation"]
    patch = chain["patch"]
    execution = chain["test_execution"]
    retest = chain["controlled_retest"]
    fix = chain["fix_verification"]
    outcome = chain["outcome"]
    payload = {
        "report_version": int(prior) + 1,
        "root_cause_analysis_id": analysis.analysis_id if analysis else None,
        "root_cause_analysis_version": analysis.analysis_version if analysis else None,
        "review_decision_id": review.id if review else None,
        "remediation_diagnosis_id": diagnosis.diagnosis_id if diagnosis else None,
        "remediation_action_id": action.remediation_action_id if action else None,
        "implementation_id": implementation.implementation_id if implementation else None,
        "patch_proposal_id": patch.patch_proposal_id if patch else None,
        "test_execution_id": execution.execution_id if execution else None,
        "controlled_retest_id": retest.controlled_retest_id if retest else None,
        "fix_verification_id": fix.id if fix else None,
        "verification_outcome_id": outcome.verification_outcome_id if outcome else None,
        "evidence_snapshot_hash": analysis.evidence_snapshot_hash if analysis else None,
        "taxonomy_version": analysis.taxonomy_version if analysis else None,
        "exposure_policy_version": analysis.exposure_policy_version if analysis else None,
        "recommendation_policy_version": (
            diagnosis.recommendation_policy_version if diagnosis else None
        ),
        "workflow_chain_status": chain["workflow_chain_status"],
        "blocked_reasons": chain["blocked_reasons"],
        "_chain": chain,
    }
    rollbacks: list[RollbackExecution] = []
    if hasattr(db, "scalars"):
        rollbacks = list(
            db.scalars(
                select(RollbackExecution)
                .where(RollbackExecution.incident_id == incident_id)
                .order_by(RollbackExecution.id.asc())
            ).all()
        )
    ids = [row.rollback_execution_id for row in rollbacks]
    patch_id = payload["patch_proposal_id"]
    impl_id = payload["implementation_id"]
    current_rb = next(
        (
            row.rollback_execution_id
            for row in reversed(rollbacks)
            if (patch_id and row.patch_proposal_id == patch_id)
            or (impl_id and row.implementation_id == impl_id)
        ),
        ids[-1] if ids else None,
    )
    payload["rollback_execution_id"] = current_rb
    payload["rollback_execution_ids"] = ids
    return payload


def build_final_investigation_report(
    db: Session,
    incident_id: str,
    *,
    report_format: str,
    generated_by: str | None = None,
    scenario_name: str | None = "scenario_1",
) -> FinalInvestigationReport:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")

    settings = get_settings()
    all_warnings: list[str] = []
    root_strength = root_cause_evidence_strength_service.calculate_evidence_strength(
        db, incident_id
    )
    readiness = report_readiness_service.get_report_readiness(db, incident_id)
    lifecycle = _lifecycle_ids(db, incident_id)
    false_positive_terminal = (
        lifecycle["workflow_chain_status"] == "current_false_positive"
    )
    final_chain_ready = lifecycle["workflow_chain_status"] in {
        "current_complete", "current_false_positive"
    }
    exact_chain = lifecycle["_chain"]
    diagnosis_chain = exact_chain["diagnosis"]
    implementation_chain = exact_chain["implementation"]
    test_chain = exact_chain["test_execution"]
    retest_chain = exact_chain["controlled_retest"]
    outcome_chain = exact_chain["outcome"]
    patch_chain = exact_chain["patch"]
    learning_chain = (
        db.scalar(
            select(VerifiedRemediationCase).where(
                VerifiedRemediationCase.verification_outcome_id
                == outcome_chain.verification_outcome_id,
                VerifiedRemediationCase.incident_id == incident_id,
                VerifiedRemediationCase.workflow_status == "current",
            )
        )
        if outcome_chain
        else None
    )
    exact_lifecycle = {
        "workflow_chain_status": lifecycle["workflow_chain_status"],
        "blocked_reasons": lifecycle["blocked_reasons"],
        "diagnosis": (
            {
                "exact_problem": diagnosis_chain.problem_statement,
                "original_remediation": diagnosis_chain.primary_remediation,
                "generation_mode": diagnosis_chain.generation_mode,
                "model_provider": diagnosis_chain.model_provider,
                "model_name": diagnosis_chain.model_name,
                "prompt_template_version": diagnosis_chain.prompt_template_version,
                "playbook_id": diagnosis_chain.playbook_id,
                "playbook_version": diagnosis_chain.playbook_version,
                "recommendation_policy_version": diagnosis_chain.recommendation_policy_version,
                "reviewer_decision": diagnosis_chain.reviewer_decision,
                "reviewer_notes": diagnosis_chain.reviewer_notes,
                "edited_fields": list(diagnosis_chain.edited_fields or []),
                "original_payload_recorded": diagnosis_chain.original_ai_payload is not None,
                "approved_payload_recorded": diagnosis_chain.approved_payload is not None,
                "approved_remediation": diagnosis_chain.approved_payload,
                "limitations": list(diagnosis_chain.limitations or []),
            }
            if diagnosis_chain
            else None
        ),
        "implementation": (
            {
                "mode": implementation_chain.implementation_mode,
                "status": implementation_chain.status,
                "change_reference_safe": implementation_chain.change_reference_safe,
                "summary": implementation_chain.implementation_summary,
                "implemented_at": _iso(implementation_chain.implemented_at),
            }
            if implementation_chain
            else None
        ),
        "patch": (
            {
                "patch_proposal_id": patch_chain.patch_proposal_id,
                "status": patch_chain.status,
                "scope": "allowlisted_local_demo",
                "affected_files": list(patch_chain.affected_files or []),
                "safety_result": patch_chain.safety_result,
            }
            if patch_chain
            else None
        ),
        "test_execution": (
            {
                "execution_id": test_chain.execution_id,
                "profile": test_chain.test_profile,
                "profile_version": test_chain.command_profile_version,
                "status": test_chain.status,
                "safe_output_summary": test_chain.safe_output_summary,
                "raw_leakage_count": test_chain.raw_leakage_count,
            }
            if test_chain
            else None
        ),
        "controlled_retest": (
            {
                "status": retest_chain.status,
                "dimensions_match": retest_chain.dimensions_match,
                "raw_exposure_after_change": retest_chain.raw_exposure_after_change,
                "safety_status": retest_chain.safety_status,
                "service_name": retest_chain.service_name,
                "endpoint": retest_chain.endpoint,
                "exposure_location": retest_chain.exposure_location,
                "sensitive_type": retest_chain.sensitive_type,
                "component": retest_chain.component,
                "limitations": (
                    []
                    if retest_chain.dimensions_match
                    else ["Controlled retest dimensions did not match the original exposure."]
                ),
            }
            if retest_chain
            else None
        ),
        "verification_outcome": (
            {
                "verification_outcome_id": outcome_chain.verification_outcome_id,
                "result": outcome_chain.verification_result,
                "verified_by": outcome_chain.verified_by,
                "limitations": list(outcome_chain.limitations or []),
                "eligible_for_learning": outcome_chain.eligible_for_learning,
                "eligibility_reason": outcome_chain.eligibility_reason,
                "verification_rule_version": "controlled_retest_exact_chain_v1",
            }
            if outcome_chain
            else None
        ),
        "learning": (
            {
                "verified_case_id": learning_chain.verified_case_id,
                "eligible": learning_chain.eligible_for_learning,
                "reason": learning_chain.eligibility_reason,
                "policy_version": learning_chain.policy_version,
            }
            if learning_chain
            else None
        ),
        "exposure": {
            "exposure_location": retest_chain.exposure_location if retest_chain else None,
            "exposure_policy_version": lifecycle["exposure_policy_version"],
            "exposure_policy_result": "not_recorded",
            "limitations": [
                "The original exposure-policy decision is not persisted on the exact lifecycle chain."
            ],
            "verification_result": (
                "clean" if retest_chain and retest_chain.raw_exposure_after_change is False
                else "unsafe" if retest_chain and retest_chain.raw_exposure_after_change is True
                else "inconclusive"
            ),
            "masking_state": "masked_or_excluded",
        },
    }

    detections_rows = db.scalars(
        select(Detection)
        .where(Detection.incident_id == incident_id)
        .order_by(Detection.id.asc())
    ).all()
    from app.services import restricted_data_policy_service
    detections: list[FinalReportDetection] = []
    for d in detections_rows:
        if restricted_data_policy_service.is_restricted_category(
            d.sensitive_type, channel="general_report"
        ):
            continue
        masked = report_safety_service.sanitize_export_text(d.masked_value)
        all_warnings.extend(masked.warnings)
        if not masked.value:
            continue
        detections.append(
            FinalReportDetection(
                detection_id=d.detection_id,
                sensitive_type=d.sensitive_type,
                masked_value=masked.value,
                confidence=d.confidence,
                severity=d.severity.value if d.severity else None,
                detector_name=d.detector_name,
                evidence_id=d.evidence_id,
                created_at=d.created_at,
            )
        )

    evidence_rows = db.scalars(
        select(EvidenceFile)
        .where(EvidenceFile.linked_incident_id == incident_id)
        .order_by(EvidenceFile.upload_timestamp.asc(), EvidenceFile.id.asc())
    ).all()
    evidence_chain: list[FinalReportEvidenceItem] = []
    for ev in evidence_rows:
        evidence_chain.append(
            FinalReportEvidenceItem(
                evidence_id=ev.evidence_id,
                file_name=ev.file_name,
                evidence_type=ev.evidence_type.value,
                source_system=ev.source_system,
                file_hash=ev.file_hash,
                upload_timestamp=ev.upload_timestamp,
                parsing_status=ev.parsing_status.value,
                role_in_investigation=_evidence_role(ev.evidence_type),
            )
        )

    event_rows = db.scalars(
        select(NormalizedEvent)
        .where(NormalizedEvent.linked_incident_id == incident_id)
        .order_by(NormalizedEvent.timestamp.asc(), NormalizedEvent.id.asc())
    ).all()
    normalized_events: list[FinalReportNormalizedEvent] = []
    for ev in event_rows:
        msg = report_safety_service.sanitize_export_text(ev.masked_message)
        all_warnings.extend(msg.warnings)
        normalized_events.append(
            FinalReportNormalizedEvent(
                event_id=ev.event_id,
                timestamp=ev.timestamp,
                source_type=ev.source_type,
                service_name=ev.service_name,
                endpoint=ev.endpoint,
                release_version=ev.release_version,
                event_type=ev.event_type,
                masked_message=msg.value,
                severity=ev.severity.value if ev.severity else None,
            )
        )

    # Phase N: root-cause analyses are now versioned rather than replaced in
    # place, so a plain `incident_id` filter would include superseded/stale
    # batches. `list_root_cause_scores` defaults to the current version only.
    score_rows = causality_engine.list_root_cause_scores(db, incident_id)
    root_cause_ranking: list[FinalReportRootCauseItem] = []
    for s in score_rows:
        expl = report_safety_service.sanitize_export_text(s.explanation)
        all_warnings.extend(expl.warnings)
        root_cause_ranking.append(
            FinalReportRootCauseItem(
                rank=s.rank,
                cause_name=s.likely_root_cause or s.cause_name,
                confidence=s.confidence,
                confidence_band=s.confidence_band,
                supporting_evidence_ids=list(s.supporting_evidence_ids or []),
                missing_evidence=list(s.missing_evidence or []),
                explanation=expl.value,
                score_breakdown=list(s.score_breakdown or []),
                matched_signals=list(s.matched_signals or []),
                negative_signals=list(s.negative_signals or []),
                correlation_reasons=list(s.correlation_reasons or []),
                contradicting_evidence=list(s.contradicting_evidence or []),
                evidence_roles=list(s.evidence_roles or []),
                suggested_actions=list(s.suggested_actions or []),
            )
        )
    if not root_cause_ranking:
        try:
            trace = causality_engine.get_incident_trace(db, incident_id)
            for cause in trace.get("likely_root_causes") or []:
                expl = report_safety_service.sanitize_export_text(cause.get("explanation"))
                all_warnings.extend(expl.warnings)
                root_cause_ranking.append(
                    FinalReportRootCauseItem(
                        rank=cause.get("rank"),
                        cause_name=cause.get("likely_root_cause") or "unknown",
                        confidence=cause.get("confidence"),
                        confidence_band=cause.get("confidence_band"),
                        supporting_evidence_ids=list(cause.get("supporting_evidence_ids") or []),
                        missing_evidence=list(cause.get("missing_evidence") or []),
                        explanation=expl.value,
                        score_breakdown=list(cause.get("score_breakdown") or []),
                        matched_signals=list(cause.get("matched_signals") or []),
                        negative_signals=list(cause.get("negative_signals") or []),
                        correlation_reasons=list(cause.get("correlation_reasons") or []),
                        contradicting_evidence=list(cause.get("contradicting_evidence") or []),
                        evidence_roles=list(cause.get("evidence_roles") or []),
                        suggested_actions=list(cause.get("suggested_actions") or []),
                    )
                )
        except KeyError:
            pass

    scanner_rows = db.scalars(
        select(ScannerEvidenceRecord)
        .where(ScannerEvidenceRecord.linked_incident_id == incident_id)
        .order_by(ScannerEvidenceRecord.imported_at.asc())
    ).all()
    scannerbridge_evidence: list[FinalReportScannerEvidence] = []
    for rec in scanner_rows:
        mv = report_safety_service.sanitize_export_text(rec.masked_value)
        all_warnings.extend(mv.warnings)
        scannerbridge_evidence.append(
            FinalReportScannerEvidence(
                scanner_evidence_id=rec.scanner_evidence_id,
                source_format=rec.source_format,
                finding_category=rec.scanner_category,
                detector_name=rec.detector_name,
                masked_value=mv.value,
                source_file=rec.source_file,
                line_number=rec.line_number,
                severity=rec.severity.value if rec.severity else None,
                confidence=rec.confidence,
                causal_relevance_score=rec.causal_relevance_score,
                linked_incident_id=rec.linked_incident_id,
            )
        )

    # Live Privacy Monitor summary: masked alerts linked to this incident.
    alert_rows = db.scalars(
        select(PrivacyAlert)
        .where(PrivacyAlert.linked_incident_id == incident_id)
        .order_by(PrivacyAlert.alert_time.asc(), PrivacyAlert.id.asc())
    ).all()
    live_alerts: list[FinalReportLiveAlertItem] = []
    for alert in alert_rows:
        masked_values: list[str] = []
        for raw_masked in alert.masked_values or []:
            mv = report_safety_service.sanitize_export_text(str(raw_masked))
            all_warnings.extend(mv.warnings)
            if mv.value:
                masked_values.append(mv.value)
        live_alerts.append(
            FinalReportLiveAlertItem(
                alert_id=alert.alert_id,
                alert_time=alert.alert_time,
                first_seen=alert.alert_time,
                last_seen=alert.updated_at,
                repeat_count=1,
                source_type=alert.source_type,
                source_name=alert.source_name,
                service_name=alert.service_name,
                endpoint=alert.endpoint,
                severity=alert.severity.value if alert.severity else None,
                status=alert.status,
                sensitive_types=[str(t) for t in (alert.sensitive_types or [])],
                masked_values=masked_values,
                evidence_id=alert.evidence_id,
            )
        )
    came_from_live = incident_id.startswith("INC-LIVE-") or bool(live_alerts)
    live_strength = str(root_strength["evidence_strength_level"]).replace("_", " ")
    missing_live_evidence = list(root_strength["missing_evidence"])
    source_counts: dict[str, int] = {}
    for evidence in evidence_rows:
        label = _evidence_role(evidence.evidence_type)
        source_counts[label] = source_counts.get(label, 0) + 1
    alert_evidence_ids = {alert.evidence_id for alert in alert_rows if alert.evidence_id}
    non_live_evidence = [
        evidence for evidence in evidence_rows if evidence.evidence_id not in alert_evidence_ids
    ]
    has_scanner_source = bool(scannerbridge_evidence) or any(
        evidence.evidence_type == EvidenceType.SCANNER_BRIDGE_IMPORT
        for evidence in evidence_rows
    )
    has_cicd_source = any(
        evidence.evidence_type.value in TECHNICAL_EVIDENCE_TYPES
        and evidence.evidence_type != EvidenceType.SCANNER_BRIDGE_IMPORT
        for evidence in evidence_rows
    )
    if came_from_live:
        incident_source = "Mixed Evidence" if non_live_evidence else "Live Monitor"
    elif has_scanner_source and (len(evidence_rows) > 1 or has_cicd_source):
        incident_source = "Mixed Evidence"
    elif has_scanner_source:
        incident_source = "ScannerBridge-NP"
    elif has_cicd_source:
        incident_source = "CI/CD Evidence"
    elif evidence_rows:
        incident_source = "Evidence Import"
    else:
        incident_source = "Manual creation"
    live_monitor_summary = FinalReportLiveMonitorSummary(
        source=incident_source,
        linked_alert_count=len(live_alerts),
        alerts=live_alerts,
        evidence_strength=live_strength,
        missing_evidence=missing_live_evidence,
        evidence_source_summary=source_counts,
        alert_to_incident_flow=(
            f"{len(live_alerts)} masked privacy alert(s) were linked to incident {incident_id}."
            if live_alerts
            else "No linked live alert was available at report generation time."
        ),
        limitations=[
            "Live alerts and uploaded logs are symptom and timeline evidence; they do not establish cause by themselves.",
            "Evidence strength reflects only evidence available at report generation time.",
            "Human review is required before remediation or closure decisions.",
        ],
    )


    ai_remediation_rows = db.scalars(
        select(AIRemediationSuggestion)
        .where(AIRemediationSuggestion.incident_id == incident_id)
        .order_by(AIRemediationSuggestion.requested_at.desc(), AIRemediationSuggestion.id.desc())
    ).all()
    ai_remediation_suggestions: list[dict[str, Any]] = []
    remediation_actions: list[str] = []
    for item in ai_remediation_rows:
        summary = report_safety_service.sanitize_export_text(item.suggestion_summary)
        notes = report_safety_service.sanitize_export_text(item.reviewer_notes)
        all_warnings.extend(summary.warnings)
        all_warnings.extend(notes.warnings)
        ai_remediation_suggestions.append(
            {
                "suggestion_id": item.suggestion_id,
                "status": item.status,
                "reviewer_decision": item.reviewer_decision,
                "suggestion_summary": summary.value,
                "likely_issue_area": item.likely_issue_area,
                "remediation_actions": list(item.remediation_actions or []),
                "retest_evidence_required": list(item.retest_evidence_required or []),
                "limitations": list(item.limitations or [])
                + ["AI remediation suggestions are advisory and require human review."],
                "human_review_required": item.human_review_required,
                "reviewer_notes": notes.value,
                "accepted_as_remediation_action_id": item.accepted_as_remediation_action_id,
            }
        )
        if item.accepted_as_remediation_action_id and item.reviewer_decision in {
            "accepted",
            "edited",
        }:
            for action in item.remediation_actions or []:
                safe_action = report_safety_service.sanitize_export_text(str(action))
                all_warnings.extend(safe_action.warnings)
                if safe_action.value:
                    remediation_actions.append(safe_action.value)
    exact_action = exact_chain["action"]
    remediation_action_rows = [exact_action] if exact_action else []
    remediation_actions = []
    remediation_action_records: list[dict[str, Any]] = []
    for item in remediation_action_rows:
        description = report_safety_service.sanitize_export_text(item.action_description)
        component = report_safety_service.sanitize_export_text(item.affected_component)
        owner = report_safety_service.sanitize_export_text(item.assigned_owner)
        notes = report_safety_service.sanitize_export_text(item.completion_notes)
        all_warnings.extend(
            description.warnings + component.warnings + owner.warnings + notes.warnings
        )
        if description.value:
            remediation_actions.append(description.value)
        remediation_action_records.append(
            {
                "remediation_action_id": item.remediation_action_id,
                "action_type": item.action_type,
                "action_description": description.value,
                "affected_component": component.value,
                "assigned_owner": owner.value,
                "status": item.status,
                "priority": item.priority,
                "target_date": item.target_date.isoformat() if item.target_date else None,
                "retest_required": item.retest_required,
                "completion_notes": notes.value,
                "created_at": _iso(item.created_at),
                "updated_at": _iso(item.updated_at),
                "completed_at": _iso(item.completed_at),
                "human_saved": True,
            }
        )
    if not remediation_actions:
        remediation_actions.append(
            "No remediation action has been recorded."
        )
    llm_row = db.scalar(
        select(LlmReport)
        .where(LlmReport.incident_id == incident_id)
        .order_by(LlmReport.created_at.desc(), LlmReport.id.desc())
        .limit(1)
    )
    guarded = FinalReportGuardedExplanation(
        human_review_required=True,
        not_generated_message="Guarded explanation was not generated for this incident.",
    )
    if llm_row:
        if llm_row.is_encrypted and llm_row.output_encrypted:
            out = field_encryption_service.decrypt_json(llm_row.output_encrypted)
        else:
            out = llm_row.output_json or {}
        expl_text = report_safety_service.sanitize_export_text(
            out.get("likely_cause_explanation") or out.get("incident_summary")
        )
        all_warnings.extend(expl_text.warnings)
        method = "local guarded LLM" if llm_row.provider_used == "ollama" else "template"
        if llm_row.provider_used == "template":
            method = "template"
        guarded = FinalReportGuardedExplanation(
            explanation_text=expl_text.value,
            explanation_method=method,
            safety_status=llm_row.safety_status,
            overclaim_check="passed" if not expl_text.warnings else "sanitized",
            human_review_required=True,
            not_generated_message=None,
        )

    exact_review = exact_chain["review"]
    human_review = FinalReportHumanReview(
        not_completed_message="Human review has not yet been completed.",
    )
    if exact_review:
        latest = exact_review
        comment = report_safety_service.sanitize_export_text(latest.comment)
        reason = report_safety_service.sanitize_export_text(latest.reason)
        evidence_limitations = report_safety_service.sanitize_export_text(
            latest.evidence_limitations
        )
        relied_on: list[str] = []
        for evidence_id in latest.evidence_relied_on or []:
            safe_id = report_safety_service.sanitize_export_text(str(evidence_id))
            all_warnings.extend(safe_id.warnings)
            if safe_id.value:
                relied_on.append(safe_id.value)
        all_warnings.extend(
            comment.warnings + reason.warnings + evidence_limitations.warnings
        )
        reviewer_label = str(latest.reviewer_id) if latest.reviewer_id else None
        if latest.reviewer_id:
            user = db.get(User, latest.reviewer_id)
            if user:
                reviewer_label = user.email
        human_review = FinalReportHumanReview(
            reviewer=reviewer_label,
            decision=latest.decision,
            comment=comment.value,
            reason=reason.value,
            evidence_relied_on=relied_on,
            evidence_limitations=evidence_limitations.value,
            missing_evidence_acknowledged=latest.missing_evidence_acknowledged,
            timestamp=latest.timestamp,
            not_completed_message=None,
        )

    fv_row = exact_chain["fix_verification"]
    fix_verification = FinalReportFixVerification(
        not_completed_message="Fix verification has not yet been completed.",
    )
    if fv_row:
        fix_verification = FinalReportFixVerification(
            verification_status=fv_row.verification_status.value,
            checks_run=list(fv_row.checks_run or []),
            passed_checks=list(fv_row.passed_checks or []),
            failed_checks=list(fv_row.failed_checks or []),
            evidence_used=list(fv_row.evidence_used or []),
            timestamp=fv_row.timestamp,
            not_completed_message=None,
        )

    evidence_ids = [e.evidence_id for e in evidence_rows]
    audit_stmt = select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(40)
    if evidence_ids:
        audit_stmt = audit_stmt.where(
            or_(
                AuditLog.target_id == incident_id,
                AuditLog.target_id.in_(evidence_ids),
            )
        )
    else:
        audit_stmt = audit_stmt.where(AuditLog.target_id == incident_id)
    audit_rows = db.scalars(audit_stmt).all()
    audit_summary: list[FinalReportAuditEntry] = []
    for row in audit_rows:
        safe_row = audit_service.audit_log_to_safe_read(row)
        details = safe_row.get("details") or {}
        if isinstance(details, dict):
            cleaned_details, detail_warnings = report_safety_service.sanitize_final_report_dict(
                {"details": details}
            )
            all_warnings.extend(detail_warnings)
            details = cleaned_details.get("details") or {}
        audit_summary.append(
            FinalReportAuditEntry(
                actor=str(safe_row.get("actor_id")) if safe_row.get("actor_id") else None,
                action=safe_row["action"],
                target_type=safe_row.get("target_type"),
                target_id=safe_row.get("target_id"),
                timestamp=safe_row.get("timestamp"),
                safe_details=details if isinstance(details, dict) else {},
            )
        )

    top = root_cause_ranking[0] if root_cause_ranking else None
    summary_text = report_safety_service.sanitize_export_text(incident.summary)
    all_warnings.extend(summary_text.warnings)

    executive = FinalReportExecutiveSummary(
        incident_summary=summary_text.value,
        affected_service=incident.affected_service,
        affected_endpoint=incident.affected_endpoint,
        severity=incident.severity.value if incident.severity else None,
        top_likely_cause=root_strength.get("likely_root_cause"),
        confidence_band=root_strength.get("confidence_level"),
        evidence_strength_level=str(
            root_strength.get("evidence_strength_level", "weak")
        ).replace("_", " "),
        confidence_cap=root_strength.get("confidence_cap"),
        confidence_limitations=list(root_strength.get("limitations") or []),
        human_review_status=(
            "completed" if exact_review else "pending — human review required"
        ),
        fix_verification_status=(
            "not applicable - rejected false positive by exact human review"
            if false_positive_terminal
            else fv_row.verification_status.value
            if fv_row
            else "not completed — requires verification"
        ),
    )
    explainability_summary = {
        "why_ranked_highest": (top.matched_signals[:4] if top else []),
        "root_cause_score_breakdown": (top.score_breakdown if top else []),
        "evidence_role_summary": (top.evidence_roles if top else []),
        "contradicting_evidence": (top.contradicting_evidence if top else []),
        "missing_evidence_suggestions": (top.suggested_actions if top else []),
    }
    evidence_graph_summary = {
        "node_types": [
            "incident",
            "evidence",
            "normalized_event",
            "detection",
            "root_cause",
            "review",
            "verification",
        ],
        "edge_relationships": [
            "has_evidence",
            "contains_masked_detection",
            "normalized_as",
            "supported_by",
            "contradicted_by",
            "time_correlated_with",
            "same_endpoint_as",
            "same_service_as",
            "verified_by",
            "requires_human_review",
        ],
    }

    report = FinalInvestigationReport(
        metadata=FinalReportMetadata(
            incident_id=incident_id,
            generated_at=datetime.now(timezone.utc),
            generated_by=generated_by,
            system_version=settings.api_version,
            report_format=report_format,
            scenario_name=scenario_name,
            report_ready=bool(
                readiness.report_ready
                and final_chain_ready
            ),
            report_label=(
                readiness.report_label
                if readiness.report_ready
                and final_chain_ready
                else "Draft report - investigation stages remain incomplete."
            ),
            blocking_items=list(
                dict.fromkeys(readiness.blocking_items + lifecycle["blocked_reasons"])
            ),
            report_version=lifecycle["report_version"],
            root_cause_analysis_id=lifecycle["root_cause_analysis_id"],
            root_cause_analysis_version=lifecycle["root_cause_analysis_version"],
            evidence_snapshot_hash=lifecycle["evidence_snapshot_hash"],
            review_decision_id=lifecycle["review_decision_id"],
            remediation_diagnosis_id=lifecycle["remediation_diagnosis_id"],
            remediation_action_id=lifecycle["remediation_action_id"],
            implementation_id=lifecycle["implementation_id"],
            patch_proposal_id=lifecycle["patch_proposal_id"],
            test_execution_id=lifecycle["test_execution_id"],
            controlled_retest_id=lifecycle["controlled_retest_id"],
            fix_verification_id=lifecycle["fix_verification_id"],
            verification_outcome_id=lifecycle["verification_outcome_id"],
            rollback_execution_id=lifecycle.get("rollback_execution_id"),
            rollback_execution_ids=list(lifecycle.get("rollback_execution_ids") or []),
            workflow_chain_status=lifecycle["workflow_chain_status"],
            disposition=(
                "rejected_false_positive"
                if false_positive_terminal
                else "verified_remediation"
                if lifecycle["workflow_chain_status"] == "current_complete"
                else "investigation_incomplete"
            ),
            taxonomy_version=lifecycle["taxonomy_version"],
            exposure_policy_version=lifecycle["exposure_policy_version"],
            recommendation_policy_version=lifecycle["recommendation_policy_version"],
        ),
        executive_summary=executive,
        incident=FinalReportIncidentSection(
            incident_id=incident.incident_id,
            title=incident.title,
            affected_service=incident.affected_service,
            affected_endpoint=incident.affected_endpoint,
            status=incident.status.value,
            severity=incident.severity.value if incident.severity else None,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            summary=summary_text.value,
        ),
        live_monitor_summary=live_monitor_summary,
        detections=detections,
        evidence_chain=evidence_chain,
        normalized_events=normalized_events,
        root_cause_ranking=root_cause_ranking,
        root_cause_evidence_strength=root_strength,
        scannerbridge_evidence=scannerbridge_evidence,
        ai_remediation_suggestions=ai_remediation_suggestions,
        remediation_actions=list(dict.fromkeys(remediation_actions)),
        remediation_action_records=remediation_action_records,
        retest_evidence=[
            item
            for item in evidence_chain
            if item.evidence_type
            in {EvidenceType.FIXED_LOG.value, EvidenceType.FIXED_SCAN.value}
        ],
        guarded_explanation=guarded,
        human_review=human_review,
        fix_verification=fix_verification,
        audit_summary=audit_summary,
        recommendations=_derive_recommendations(
            incident,
            top.cause_name if top else None,
            bool(scannerbridge_evidence),
            fv_row is not None,
        ),
        explainability_summary=explainability_summary,
        evidence_graph_summary=evidence_graph_summary,
        safe_conclusion=(
            "The current exact human review rejected this investigation as a false positive; "
            "no remediation or fix-verification outcome is claimed."
            if false_positive_terminal
            else "Evidence suggests the top-ranked item is the strongest likely cause. "
            "Human review is required before remediation conclusions."
        ),
        privacy_safety_controls=list(PRIVACY_CONTROLS),
        limitations=list(LIMITATIONS)
        + [ROOT_CAUSE_NOTE]
        + list(root_strength.get("limitations") or [])
        + readiness.blocking_items
        + ([SCANNER_NOTE] if scannerbridge_evidence else []),
        appendix={
            "linked_evidence_ids": [e.evidence_id for e in evidence_chain],
            "report_generation_timestamp": datetime.now(timezone.utc).isoformat(),
            "report_format": report_format,
            "system_version": settings.api_version,
            "scenario_name": scenario_name,
            "report_readiness_checks": readiness.checks.model_dump(),
            "report_ready": bool(
                readiness.report_ready
                and final_chain_ready
            ),
            "exact_lifecycle": exact_lifecycle,
            "disposition": (
                "rejected_false_positive"
                if false_positive_terminal
                else "verified_remediation"
                if lifecycle["workflow_chain_status"] == "current_complete"
                else "investigation_incomplete"
            ),
            "notes": [
                ROOT_CAUSE_NOTE,
                SCANNER_NOTE if scannerbridge_evidence else None,
            ],
        },
        safety_warnings=list(dict.fromkeys(all_warnings)),
    )

    payload, extra_warnings = report_safety_service.sanitize_final_report_dict(
        report.model_dump(mode="json")
    )
    payload, restricted_present = restricted_data_policy_service.sanitize_payload(
        payload,
        channel="general_report",
    )
    if restricted_present:
        extra_warnings.append("Restricted internal categories were omitted from the report.")
    report = FinalInvestigationReport.model_validate(payload)
    merged_warnings = list(dict.fromkeys(report.safety_warnings + extra_warnings))
    return report.model_copy(update={"safety_warnings": merged_warnings})


def final_report_to_json(report: FinalInvestigationReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, default=str)


def persist_final_report_export(db: Session, report: FinalInvestigationReport) -> Report:
    """Persist the exact immutable provenance represented by one export."""

    meta = report.metadata
    stored = {"report": report.model_dump(mode="json")}
    row = Report(
        incident_id=meta.incident_id,
        report_type=f"final_{meta.report_format}",
        report_version=meta.report_version,
        root_cause_analysis_id=meta.root_cause_analysis_id,
        root_cause_analysis_version=meta.root_cause_analysis_version,
        evidence_snapshot_hash=meta.evidence_snapshot_hash,
        review_decision_id=meta.review_decision_id,
        remediation_diagnosis_id=meta.remediation_diagnosis_id,
        remediation_action_id=meta.remediation_action_id,
        implementation_id=meta.implementation_id,
        patch_proposal_id=meta.patch_proposal_id,
        test_execution_id=meta.test_execution_id,
        controlled_retest_id=meta.controlled_retest_id,
        fix_verification_id=meta.fix_verification_id,
        verification_outcome_id=meta.verification_outcome_id,
        recommendation_policy_version=meta.recommendation_policy_version,
        taxonomy_version=meta.taxonomy_version,
        exposure_policy_version=meta.exposure_policy_version,
        workflow_chain_status=meta.workflow_chain_status,
    )
    if field_encryption_service.encryption_enabled():
        encrypted = field_encryption_service.encrypt_json(
            value=stored,
            table="reports",
            record_id=meta.incident_id,
            field="content_json",
            extra=f"final_{meta.report_format}",
        )
        row.content_encrypted = encrypted
        row.content_crypto_metadata = {"kid": encrypted.get("kid")}
        row.is_encrypted = True
        row.content_json = None
    else:
        row.content_json = stored
        row.is_encrypted = False
    db.add(row)
    db.flush()
    return row


def render_final_report_html(report: FinalInvestigationReport) -> str:
    """Render full final investigation report HTML."""

    def esc(value: object) -> str:
        return html.escape("" if value is None else str(value))

    r = report

    def section(title: str, body: str) -> str:
        return f"<h2>{esc(title)}</h2>{body}"

    det_rows = ""
    for d in r.detections:
        det_rows += (
            "<tr>"
            f"<td>{esc(d.detection_id)}</td>"
            f"<td>{esc(d.sensitive_type)}</td>"
            f"<td>{esc(d.masked_value)}</td>"
            f"<td>{esc(d.severity)}</td>"
            f"<td>{esc(d.evidence_id)}</td>"
            "</tr>"
        )

    ev_rows = ""
    for e in r.evidence_chain:
        ev_rows += (
            "<tr>"
            f"<td>{esc(e.evidence_id)}</td>"
            f"<td>{esc(e.evidence_type)}</td>"
            f"<td>{esc(e.file_name)}</td>"
            f"<td>{esc(e.role_in_investigation)}</td>"
            f"<td>{esc(e.parsing_status)}</td>"
            "</tr>"
        )

    rc_items = ""
    for c in r.root_cause_ranking:
        rc_items += (
            f"<li><strong>Rank {esc(c.rank)}</strong> {esc(c.cause_name)} "
            f"(confidence band: {esc(c.confidence_band)}) — "
            f"supporting evidence: {esc(', '.join(c.supporting_evidence_ids))}</li>"
        )

    scanner_rows = ""
    for s in r.scannerbridge_evidence:
        scanner_rows += (
            "<tr>"
            f"<td>{esc(s.scanner_evidence_id)}</td>"
            f"<td>{esc(s.source_format)}</td>"
            f"<td>{esc(s.detector_name)}</td>"
            f"<td>{esc(s.masked_value)}</td>"
            f"<td>{esc(s.causal_relevance_score)}</td>"
            "</tr>"
        )

    live_alert_rows = ""
    for alert in r.live_monitor_summary.alerts:
        live_alert_rows += (
            "<tr>"
            f"<td>{esc(alert.alert_id)}</td>"
            f"<td>{esc(alert.first_seen or alert.alert_time)}</td>"
            f"<td>{esc(alert.last_seen)}</td>"
            f"<td>{esc(alert.repeat_count)}</td>"
            f"<td>{esc(alert.source_name or alert.source_type)}</td>"
            f"<td>{esc(alert.service_name)}</td>"
            f"<td>{esc(alert.endpoint)}</td>"
            f"<td>{esc(alert.severity)}</td>"
            f"<td>{esc(', '.join(alert.sensitive_types))}</td>"
            f"<td>{esc(', '.join(alert.masked_values))}</td>"
            "</tr>"
        )
    live_source_items = "".join(
        f"<li>{esc(label)}: {esc(count)}</li>"
        for label, count in r.live_monitor_summary.evidence_source_summary.items()
    )
    live_missing_items = "".join(
        f"<li>{esc(item)}</li>" for item in r.live_monitor_summary.missing_evidence
    )
    live_limit_items = "".join(
        f"<li>{esc(item)}</li>" for item in r.live_monitor_summary.limitations
    )

    ai_items = ""
    for item in r.ai_remediation_suggestions:
        actions = "".join(f"<li>{esc(action)}</li>" for action in (item.get("remediation_actions") or []))
        retest = "".join(f"<li>{esc(ev)}</li>" for ev in (item.get("retest_evidence_required") or []))
        ai_items += (
            f"<h3>{esc(item.get('suggestion_id'))} - {esc(item.get('status'))}</h3>"
            f"<p>{esc(item.get('suggestion_summary'))}</p>"
            f"<p><strong>Likely issue area:</strong> {esc(item.get('likely_issue_area'))}</p>"
            f"<p><strong>Reviewer decision:</strong> {esc(item.get('reviewer_decision'))}</p>"
            f"<p><strong>Remediation actions:</strong></p><ul>{actions}</ul>"
            f"<p><strong>Retest evidence required:</strong></p><ul>{retest}</ul>"
            "<p><em>AI remediation suggestions are advisory and require human review.</em></p>"
        )
    recs = "".join(f"<li>{esc(x)}</li>" for x in r.recommendations)
    remediation_items = "".join(f"<li>{esc(x)}</li>" for x in r.remediation_actions)
    remediation_record_items = "".join(
        "<li>"
        f"{esc(item.get('remediation_action_id'))}: {esc(item.get('status'))} - "
        f"{esc(item.get('affected_component'))}"
        "</li>"
        for item in r.remediation_action_records
    )
    retest_items = "".join(
        f"<li>{esc(item.evidence_id)} - {esc(item.evidence_type)}</li>"
        for item in r.retest_evidence
    )
    limits = "".join(f"<li>{esc(x)}</li>" for x in r.limitations)
    controls = "".join(f"<li>{esc(x)}</li>" for x in r.privacy_safety_controls)

    expl = r.guarded_explanation.explanation_text or r.guarded_explanation.not_generated_message

    review_block = (
        f"<p>Reviewer: {esc(r.human_review.reviewer)}</p>"
        f"<p>Decision: {esc(r.human_review.decision)}</p>"
        f"<p>Reason: {esc(r.human_review.reason)}</p>"
        f"<p>Comment: {esc(r.human_review.comment)}</p>"
        f"<p>Evidence limitations: {esc(r.human_review.evidence_limitations)}</p>"
        if r.human_review.reviewer or r.human_review.decision
        else f"<p>{esc(r.human_review.not_completed_message)}</p>"
    )

    fv = r.fix_verification
    fv_block = (
        f"<p>Status: {esc(fv.verification_status)}</p>"
        f"<p>Checks run: {esc(', '.join(fv.checks_run))}</p>"
        f"<p>Passed: {esc(', '.join(fv.passed_checks))}</p>"
        f"<p>Failed: {esc(', '.join(fv.failed_checks))}</p>"
        if fv.verification_status
        else f"<p>{esc(fv.not_completed_message)}</p>"
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>PrivacyTrace-NP Final Investigation Report — {esc(r.metadata.incident_id)}</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 2rem; line-height: 1.55; color: #1a202c; }}
    h1 {{ font-size: 1.75rem; color: #1a365d; }}
    h2 {{ font-size: 1.2rem; margin-top: 1.5rem; color: #2c5282; border-bottom: 1px solid #cbd5e0; }}
    table {{ border-collapse: collapse; width: 100%; margin: 0.75rem 0; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #cbd5e0; padding: 0.4rem 0.5rem; text-align: left; }}
    th {{ background: #edf2f7; }}
    .notice {{ background: #fffaf0; border-left: 4px solid #dd6b20; padding: 1rem; margin: 1rem 0; }}
    .cover {{ page-break-after: always; }}
  </style>
</head>
<body>
  <div class="cover">
    <h1>PrivacyTrace-NP Final Investigation Report</h1>
    <p><strong>Incident ID:</strong> {esc(r.metadata.incident_id)}</p>
    <p><strong>Generated:</strong> {esc(r.metadata.generated_at)}</p>
    <p><strong>Generated by:</strong> {esc(r.metadata.generated_by or 'system')}</p>
    <p><strong>System version:</strong> {esc(r.metadata.system_version)}</p>
    <p class="notice"><strong>{esc(r.metadata.report_label)}</strong></p>
    <p class="notice">{esc(CONFIDENTIALITY_NOTE)}</p>
  </div>
  {section("Executive Summary", f"""
    <ul>
      <li><strong>Service:</strong> {esc(r.executive_summary.affected_service)}</li>
      <li><strong>Endpoint:</strong> {esc(r.executive_summary.affected_endpoint)}</li>
      <li><strong>Severity:</strong> {esc(r.executive_summary.severity)}</li>
      <li><strong>Top likely cause:</strong> {esc(r.executive_summary.top_likely_cause)}</li>
      <li><strong>Confidence band:</strong> {esc(r.executive_summary.confidence_band)}</li>
      <li><strong>Evidence strength:</strong> {esc(r.executive_summary.evidence_strength_level)}</li>
      <li><strong>Confidence cap:</strong> {esc(r.executive_summary.confidence_cap)}</li>
      <li><strong>Human review:</strong> {esc(r.executive_summary.human_review_status)}</li>
      <li><strong>Fix verification:</strong> {esc(r.executive_summary.fix_verification_status)}</li>
    </ul>
    <p>{esc(r.executive_summary.incident_summary)}</p>
  """)}
  {section("Incident Details", f"""
    <ul>
      <li><strong>Title:</strong> {esc(r.incident.title)}</li>
      <li><strong>Status:</strong> {esc(r.incident.status)}</li>
      <li><strong>First seen:</strong> {esc(r.incident.first_seen)}</li>
      <li><strong>Last seen:</strong> {esc(r.incident.last_seen)}</li>
    </ul>
    <p>{esc(r.incident.summary)}</p>
  """)}
  {section("Live Monitor Summary and Privacy Alert Timeline", f"""
    <ul>
      <li><strong>Incident source:</strong> {esc(r.live_monitor_summary.source)}</li>
      <li><strong>Linked privacy alerts:</strong> {esc(r.live_monitor_summary.linked_alert_count)}</li>
      <li><strong>Root-cause evidence strength:</strong> {esc(r.live_monitor_summary.evidence_strength)}</li>
      <li><strong>Alert-to-incident flow:</strong> {esc(r.live_monitor_summary.alert_to_incident_flow)}</li>
    </ul>
    <table><thead><tr><th>Alert</th><th>First seen</th><th>Last seen</th><th>Repeat</th><th>Source</th><th>Service</th><th>Endpoint</th><th>Severity</th><th>Sensitive types</th><th>Masked values</th></tr></thead>
    <tbody>{live_alert_rows or '<tr><td colspan="10">No linked live alerts</td></tr>'}</tbody></table>
    <h3>Evidence source summary</h3>
    <ul>{live_source_items or '<li>No linked evidence sources</li>'}</ul>
    <h3>Missing evidence</h3>
    <ul>{live_missing_items or '<li>No category-level gap identified</li>'}</ul>
    <p><em>{esc(r.live_monitor_summary.note)}</em></p>
    <ul>{live_limit_items}</ul>
  """)}
  {section("Detection Summary", f"""
    <table><thead><tr><th>ID</th><th>Type</th><th>Masked value</th><th>Severity</th><th>Evidence</th></tr></thead>
    <tbody>{det_rows or '<tr><td colspan="5">None</td></tr>'}</tbody></table>
  """)}
  {section("Evidence Chain", f"""
    <table><thead><tr><th>ID</th><th>Type</th><th>File</th><th>Role</th><th>Status</th></tr></thead>
    <tbody>{ev_rows or '<tr><td colspan="5">None</td></tr>'}</tbody></table>
  """)}
  {section("Root-Cause Ranking", f"<ol>{rc_items or '<li>None ranked</li>'}</ol><p><em>{esc(ROOT_CAUSE_NOTE)}</em></p>")}
  {section("Why this cause was ranked highest", f"""
    <ul>{"".join(f"<li>{esc(str(item.get('reason') or item))}</li>" for item in (r.explainability_summary.get('why_ranked_highest') or [])) or "<li>No explainability signals available.</li>"}</ul>
    <p><strong>Safe conclusion:</strong> {esc(r.safe_conclusion)}</p>
  """)}
  {section("Contradicting evidence", f"""
    <ul>{"".join(f"<li>{esc(str(item.get('evidence_id')))}: {esc(str(item.get('reason')))}</li>" for item in (r.explainability_summary.get('contradicting_evidence') or [])) or "<li>No contradicting evidence captured.</li>"}</ul>
  """)}
  {section("ScannerBridge-NP Supporting Evidence", f"""
    <table><thead><tr><th>ID</th><th>Format</th><th>Detector</th><th>Masked</th><th>Relevance</th></tr></thead>
    <tbody>{scanner_rows or '<tr><td colspan="5">None linked</td></tr>'}</tbody></table>
    <p><em>{esc(SCANNER_NOTE)}</em></p>
  """)}
  {section("Guarded Explanation", f"<p>{esc(expl)}</p><p>Method: {esc(r.guarded_explanation.explanation_method)}</p>")}
  {section("Human Review", review_block)}
  {section("Remediation Action", f"<ul>{remediation_items}</ul><ul>{remediation_record_items}</ul>")}
  {section("Retest Evidence", f"<ul>{retest_items or '<li>No retest evidence linked.</li>'}</ul>")}
  {section("Fix Verification", fv_block)}
  {section("Recommendations", f"<ul>{recs}</ul>")}
  {section("Privacy and Safety Controls", f"<ul>{controls}</ul>")}
  {section("Limitations", f"<ul>{limits}</ul>")}
</body>
</html>"""
    report_safety_service.validate_html_document(doc)
    return doc


def build_evidence_summary_csv(report: FinalInvestigationReport) -> str:
    def safe_cell(value: object) -> object:
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value
        return value

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "evidence_id",
            "evidence_type",
            "source_system",
            "file_name",
            "parsing_status",
            "upload_timestamp",
            "linked_incident_id",
            "role_in_investigation",
        ]
    )
    for item in report.evidence_chain:
        writer.writerow(
            [
                safe_cell(value)
                for value in [
                item.evidence_id,
                item.evidence_type,
                item.source_system or "",
                item.file_name,
                item.parsing_status,
                _iso(item.upload_timestamp) or "",
                report.metadata.incident_id,
                item.role_in_investigation,
                ]
            ]
        )
    csv_text = buffer.getvalue()
    report_safety_service.validate_text_blob(csv_text)
    return csv_text

