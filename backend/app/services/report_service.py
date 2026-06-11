"""Incident report generation (JSON and HTML) with safety validation."""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AuditLog,
    Detection,
    EvidenceFile,
    FixVerification,
    Incident,
    LlmReport,
    Report,
    ReviewDecision,
    RootCauseScore,
)
from app.services import (
    audit_service,
    causality_engine,
    field_encryption_service,
    report_safety_service,
    restricted_data_policy_service,
)
from app.services.report_safety_service import ReportSafetyError

SAFETY_STATEMENT = (
    "This report uses masked sensitive values and likely-cause wording only. "
    "Human review is required before closure. Supporting evidence IDs are cited "
    "where claims are made; missing evidence is listed explicitly."
)

FORBIDDEN_INJECTION_MARKERS = (
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
)


@dataclass
class GenerateReportResult:
    report: Report
    report_type: str
    content: dict
    html_document: str | None


class ReportServiceError(Exception):
    pass


class IncidentNotFoundError(ReportServiceError):
    pass


def _latest_llm_summary(db: Session, incident_id: str) -> dict | None:
    row = db.scalar(
        select(LlmReport)
        .where(LlmReport.incident_id == incident_id)
        .order_by(LlmReport.created_at.desc(), LlmReport.id.desc())
        .limit(1)
    )
    if not row:
        return None
    if row.is_encrypted and row.output_encrypted:
        out = field_encryption_service.decrypt_json(row.output_encrypted)
    elif row.output_json:
        out = row.output_json
    else:
        return None
    return {
        "report_id": row.report_id,
        "provider_used": row.provider_used,
        "safety_status": row.safety_status,
        "incident_summary": out.get("incident_summary"),
        "likely_cause_explanation": out.get("likely_cause_explanation"),
        "supporting_evidence_summary": out.get("supporting_evidence_summary"),
        "human_review_note": out.get("human_review_note"),
    }


def _review_summaries(db: Session, incident_id: str) -> list[dict]:
    rows = db.scalars(
        select(ReviewDecision)
        .where(ReviewDecision.incident_id == incident_id)
        .order_by(ReviewDecision.timestamp.asc(), ReviewDecision.id.asc())
    ).all()
    return [
        {
            "decision": r.decision,
            "reviewer_id": r.reviewer_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "comment": r.comment,
        }
        for r in rows
    ]


def _fix_verification_summary(db: Session, incident_id: str) -> dict | None:
    row = db.scalar(
        select(FixVerification)
        .where(FixVerification.incident_id == incident_id)
        .order_by(FixVerification.timestamp.desc(), FixVerification.id.desc())
        .limit(1)
    )
    if not row:
        return None
    return {
        "verification_status": row.verification_status.value,
        "checks_run": list(row.checks_run or []),
        "passed_checks": list(row.passed_checks or []),
        "failed_checks": list(row.failed_checks or []),
        "evidence_used": list(row.evidence_used or []),
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "human_review_required": True,
    }


def _audit_summary(db: Session, incident_id: str, limit: int = 20) -> list[dict]:
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.target_id == incident_id)
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .limit(limit)
    ).all()
    summaries = []
    for row in rows:
        safe_row = audit_service.audit_log_to_safe_read(row)
        summaries.append(
            {
                "action": safe_row["action"],
                "actor_id": safe_row["actor_id"],
                "timestamp": (
                    safe_row["timestamp"].isoformat()
                    if safe_row.get("timestamp")
                    else None
                ),
                "details": safe_row["details"],
            }
        )
    return summaries


def _masked_detections(db: Session, incident_id: str) -> list[dict]:
    rows = db.scalars(
        select(Detection)
        .where(Detection.incident_id == incident_id)
        .order_by(Detection.id.asc())
    ).all()
    from app.services import restricted_data_policy_service
    safe_rows = [
        d
        for d in rows
        if not restricted_data_policy_service.is_restricted_category(
            d.sensitive_type, channel="general_report"
        )
    ]
    return [
        {
            "detection_id": d.detection_id,
            "sensitive_type": d.sensitive_type,
            "masked_value": d.masked_value,
            "evidence_id": d.evidence_id,
            "severity": d.severity.value if d.severity else None,
            "confidence": d.confidence,
        }
        for d in safe_rows
    ]


def _linked_evidence_ids(db: Session, incident_id: str) -> list[str]:
    rows = db.scalars(
        select(EvidenceFile.evidence_id)
        .where(EvidenceFile.linked_incident_id == incident_id)
        .order_by(EvidenceFile.id.asc())
    ).all()
    return list(rows)


def build_incident_report_content(db: Session, incident_id: str) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")

    from app.services import workflow_provenance_service

    chain = workflow_provenance_service.get_exact_report_chain(db, incident_id)
    analysis = chain["analysis"]
    review = chain.get("review")
    fix = chain["fix_verification"]
    anchored_scores = list(
        db.scalars(
            select(RootCauseScore)
            .where(
                RootCauseScore.incident_id == incident_id,
                RootCauseScore.analysis_id == (analysis.analysis_id if analysis else None),
            )
            .order_by(RootCauseScore.rank.asc(), RootCauseScore.id.asc())
        ).all()
    ) if analysis else []
    trace = {
        "likely_root_causes": [
            {
                "likely_root_cause": row.likely_root_cause,
                "confidence_band": row.confidence_band,
                "confidence": row.confidence,
                "missing_evidence": list(row.missing_evidence or []),
                "recommended_fix": row.recommended_fix,
                "supporting_evidence_ids": list(row.supporting_evidence_ids or []),
            }
            for row in anchored_scores
        ],
        "missing_evidence": list(anchored_scores[0].missing_evidence or []) if anchored_scores else [],
    }
    top = (trace.get("likely_root_causes") or [None])[0] or {}

    content = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident.incident_id,
        "title": incident.title,
        "affected_service": incident.affected_service,
        "affected_endpoint": incident.affected_endpoint,
        "severity": incident.severity.value if incident.severity else None,
        "status": incident.status.value,
        "masked_detections": _masked_detections(db, incident_id),
        "linked_evidence_ids": _linked_evidence_ids(db, incident_id),
        "likely_root_causes": trace.get("likely_root_causes") or [],
        "top_likely_root_cause": top.get("likely_root_cause"),
        "confidence_band": top.get("confidence_band"),
        "confidence_score": top.get("confidence"),
        "missing_evidence": trace.get("missing_evidence") or [],
        "recommended_fix": top.get("recommended_fix"),
        "llm_explanation_summary": None,
        "human_review_decisions": ([{
            "decision": review.decision,
            "timestamp": review.timestamp.isoformat() if review.timestamp else None,
            "reason": review.reason,
        }] if review else []),
        "audit_summary": _audit_summary(db, incident_id),
        "fix_verification": ({
            "verification_status": fix.verification_status.value,
            "timestamp": fix.timestamp.isoformat() if fix.timestamp else None,
        } if fix else None),
        "workflow_chain_status": chain["workflow_chain_status"],
        "blocking_items": chain["blocked_reasons"],
        "safety_statement": SAFETY_STATEMENT,
        "wording_policy": {
            "preferred_terms": [
                "likely cause",
                "supporting evidence",
                "confidence level",
                "missing evidence",
                "human review required",
                "verification passed",
                "verification failed",
                "verification inconclusive",
            ],
            "forbidden_categories": [
                "absolute_causality_claims",
                "confirmed_blame_language",
                "guaranteed_remediation_claims",
                "automatic_closure_claims",
            ],
        },
        "human_review_required": True,
    }
    content, _restricted_present = restricted_data_policy_service.sanitize_payload(
        content,
        channel="general_report",
    )
    return content


def render_html_report(content: dict) -> str:
    """Render escaped HTML from safe structured report content."""

    def esc(value: object) -> str:
        return html.escape("" if value is None else str(value))

    detections_rows = ""
    for det in content.get("masked_detections") or []:
        detections_rows += (
            "<tr>"
            f"<td>{esc(det.get('detection_id'))}</td>"
            f"<td>{esc(det.get('sensitive_type'))}</td>"
            f"<td>{esc(det.get('masked_value'))}</td>"
            f"<td>{esc(det.get('evidence_id'))}</td>"
            "</tr>"
        )

    causes_html = ""
    for cause in content.get("likely_root_causes") or []:
        ev_ids = ", ".join(esc(e) for e in (cause.get("supporting_evidence_ids") or []))
        causes_html += (
            f"<li><strong>Rank {esc(cause.get('rank'))}</strong>: "
            f"{esc(cause.get('likely_root_cause'))} "
            f"(confidence band: {esc(cause.get('confidence_band'))}) "
            f"— supporting evidence: {ev_ids}</li>"
        )

    evidence_ids = ", ".join(esc(e) for e in (content.get("linked_evidence_ids") or []))
    missing = ", ".join(esc(m) for m in (content.get("missing_evidence") or []))
    fv = content.get("fix_verification") or {}
    llm = content.get("llm_explanation_summary") or {}

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>PrivacyTrace-NP Incident Report — {esc(content.get('incident_id'))}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; }}
    h1, h2 {{ color: #1a365d; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #cbd5e0; padding: 0.5rem; text-align: left; }}
    th {{ background: #edf2f7; }}
    .notice {{ background: #fffaf0; border-left: 4px solid #dd6b20; padding: 1rem; }}
  </style>
</head>
<body>
  <h1>PrivacyTrace-NP Incident Report</h1>
  <p class="notice">{esc(content.get('safety_statement'))}</p>
  <h2>Incident overview</h2>
  <ul>
    <li><strong>Incident ID:</strong> {esc(content.get('incident_id'))}</li>
    <li><strong>Service:</strong> {esc(content.get('affected_service'))}</li>
    <li><strong>Endpoint:</strong> {esc(content.get('affected_endpoint'))}</li>
    <li><strong>Severity:</strong> {esc(content.get('severity'))}</li>
    <li><strong>Status:</strong> {esc(content.get('status'))}</li>
  </ul>
  <h2>Masked detections</h2>
  <table>
    <thead><tr><th>Detection</th><th>Type</th><th>Masked value</th><th>Evidence</th></tr></thead>
    <tbody>{detections_rows or '<tr><td colspan="4">None recorded</td></tr>'}</tbody>
  </table>
  <h2>Linked evidence IDs</h2>
  <p>{evidence_ids or 'None'}</p>
  <h2>Likely root cause ranking</h2>
  <ol>{causes_html or '<li>No ranking available</li>'}</ol>
  <p><strong>Top likely cause:</strong> {esc(content.get('top_likely_root_cause'))}</p>
  <p><strong>Confidence band:</strong> {esc(content.get('confidence_band'))}</p>
  <p><strong>Missing evidence:</strong> {missing or 'None listed'}</p>
  <p><strong>Recommended fix:</strong> {esc(content.get('recommended_fix'))}</p>
  <h2>Guarded explanation summary</h2>
  <p>{esc(llm.get('likely_cause_explanation') or 'No guarded explanation on file.')}</p>
  <h2>Human review</h2>
  <p>Human review required: yes</p>
  <h2>Fix verification</h2>
  <p>Status: {esc(fv.get('verification_status') or 'not run')}</p>
  <p>Evidence used: {', '.join(esc(e) for e in (fv.get('evidence_used') or [])) or 'n/a'}</p>
</body>
</html>"""
    lower = doc.lower()
    for marker in FORBIDDEN_INJECTION_MARKERS:
        if marker in lower:
            raise ReportSafetyError("HTML report contains disallowed markup patterns.")
    return doc


def generate_report(
    db: Session,
    incident_id: str,
    *,
    report_type: str,
    requested_by: int | None = None,
) -> GenerateReportResult:
    if report_type not in ("json", "html"):
        raise ReportServiceError("report_type must be 'json' or 'html'")

    content = build_incident_report_content(db, incident_id)
    report_safety_service.assert_report_safe(content)

    html_document: str | None = None
    stored: dict = {"report": content}
    if report_type == "html":
        html_document = render_html_report(content)
        safety = report_safety_service.validate_html_document(html_document)
        if not safety.safe:
            raise ReportSafetyError(safety.message or "Unsafe HTML report")
        stored["html_document"] = html_document

    from app.services.final_report_service import _lifecycle_ids

    lifecycle = _lifecycle_ids(db, incident_id)
    record = Report(
        incident_id=incident_id,
        report_type=report_type,
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
        recommendation_policy_version=lifecycle["recommendation_policy_version"],
        taxonomy_version=lifecycle["taxonomy_version"],
        exposure_policy_version=lifecycle["exposure_policy_version"],
        workflow_chain_status=lifecycle["workflow_chain_status"],
    )
    if field_encryption_service.encryption_enabled():
        payload = field_encryption_service.encrypt_json(
            value=stored,
            table="reports",
            record_id=incident_id,
            field="content_json",
            extra=report_type,
        )
        record.content_json = None
        record.content_encrypted = payload
        record.content_crypto_metadata = {"kid": payload.get("kid")}
        record.is_encrypted = True
    else:
        record.content_json = stored
        record.is_encrypted = False
    db.add(record)
    db.flush()

    audit_service.log_action(
        db,
        action=audit_service.ACTION_REPORT_EXPORTED,
        actor_id=requested_by,
        target_type="incident",
        target_id=incident_id,
        details={
            "report_id": record.id,
            "report_type": report_type,
            "incident_id": incident_id,
        },
    )
    db.commit()
    db.refresh(record)

    return GenerateReportResult(
        report=record,
        report_type=report_type,
        content=content,
        html_document=html_document,
    )


def list_incident_reports(db: Session, incident_id: str) -> list[Report]:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    return list(
        db.scalars(
            select(Report)
            .where(Report.incident_id == incident_id)
            .order_by(Report.created_at.desc(), Report.id.desc())
        ).all()
    )


def report_to_safe_response(record: Report) -> dict:
    if record.is_encrypted and record.content_encrypted:
        stored = field_encryption_service.decrypt_json(record.content_encrypted)
    else:
        stored = record.content_json or {}
    content = stored.get("report") or stored
    payload = {
        "report_id": record.id,
        "incident_id": record.incident_id,
        "report_type": record.report_type,
        "created_at": record.created_at,
        "content": content,
    }
    if record.report_type == "html" and stored.get("html_document"):
        payload["html_document"] = stored["html_document"]
    report_safety_service.assert_report_safe(
        {k: v for k, v in payload.items() if k != "html_document"}
    )
    if "html_document" in payload:
        safety = report_safety_service.validate_html_document(payload["html_document"])
        if not safety.safe:
            raise ReportSafetyError(safety.message or "Unsafe stored HTML report")
    return payload


def report_history_statuses(db: Session, incident_id: str, rows: list[Report]) -> dict[int, dict]:
    """Mark the newest export matching today's exact chain as current."""

    from app.services import workflow_provenance_service

    chain = workflow_provenance_service.get_exact_report_chain(db, incident_id)
    analysis = chain["analysis"]
    outcome = chain["outcome"]
    review = chain.get("review")
    current_id: int | None = None
    if chain["workflow_chain_status"] == "current_complete" and analysis and outcome:
        matching = [
            row for row in rows
            if row.root_cause_analysis_id == analysis.analysis_id
            and row.root_cause_analysis_version == analysis.analysis_version
            and row.evidence_snapshot_hash == analysis.evidence_snapshot_hash
            and row.verification_outcome_id == outcome.verification_outcome_id
            and row.workflow_chain_status == "current_complete"
        ]
        if matching:
            current_id = max(matching, key=lambda row: (row.report_version, row.id)).id
    elif chain["workflow_chain_status"] == "current_false_positive" and analysis and review:
        matching = [
            row for row in rows
            if row.root_cause_analysis_id == analysis.analysis_id
            and row.root_cause_analysis_version == analysis.analysis_version
            and row.evidence_snapshot_hash == analysis.evidence_snapshot_hash
            and row.review_decision_id == review.id
            and row.verification_outcome_id is None
            and row.workflow_chain_status == "current_false_positive"
        ]
        if matching:
            current_id = max(matching, key=lambda row: (row.report_version, row.id)).id
    return {
        row.id: {
            "history_status": (
                "current_export" if row.id == current_id
                else "superseded_export" if row.report_type.startswith("final_")
                else "historical_report"
            ),
            "current_chain_match_at_export": row.id == current_id,
        }
        for row in rows
    }
