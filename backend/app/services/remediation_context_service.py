"""Build a deterministic, masked Remediation Evidence Package for AI remediation."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cicd_evidence import CicdEvidence
from app.models.detection import Detection
from app.models.evidence_file import EvidenceFile
from app.models.fix_verification import FixVerification
from app.models.incident import Incident
from app.models.normalized_event import NormalizedEvent
from app.models.privacy_alert import PrivacyAlert
from app.models.root_cause_score import RootCauseScore
from app.models.sast_finding import SastFinding
from app.models.scanner_evidence_record import ScannerEvidenceRecord
from app.models.secret_finding import SecretFinding
from app.services import causality_engine, report_safety_service, restricted_data_policy_service
from app.services.root_cause_evidence_strength_service import calculate_evidence_strength


def _safe_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    if not stripped:
        return None
    return report_safety_service.sanitize_export_text(stripped).value


def _top_root_cause(scores: list[RootCauseScore]) -> RootCauseScore | None:
    if not scores:
        return None
    fresh = [row for row in scores if not row.stale]
    pool = fresh or scores
    return sorted(
        pool,
        key=lambda row: (row.rank if row.rank is not None else 10_000, -(row.confidence or 0.0)),
    )[0]


def _collect_exposure_locations(alerts: list[PrivacyAlert]) -> list[str]:
    locations: list[str] = []
    for alert in alerts:
        if alert.exposure_location:
            locations.append(alert.exposure_location)
        for finding in alert.alert_findings or []:
            if isinstance(finding, dict):
                loc = finding.get("exposure_location")
                if loc:
                    locations.append(str(loc))
    return list(dict.fromkeys(locations))


def _collect_sensitive_types(detections: list[Detection], alerts: list[PrivacyAlert]) -> list[str]:
    types: list[str] = []
    for detection in detections:
        if detection.sensitive_type:
            types.append(detection.sensitive_type)
    for alert in alerts:
        for item in alert.sensitive_types or []:
            types.append(str(item))
    return list(dict.fromkeys(types))


def _safe_correlation_ids(events: list[NormalizedEvent]) -> dict[str, list[str]]:
    trace_ids: list[str] = []
    request_ids: list[str] = []
    correlation_ids: list[str] = []
    for event in events:
        if event.trace_id:
            trace_ids.append(event.trace_id)
        if event.request_id:
            request_ids.append(event.request_id)
        if event.correlation_id:
            correlation_ids.append(event.correlation_id)
    return {
        "trace_ids": list(dict.fromkeys(trace_ids))[:10],
        "request_ids": list(dict.fromkeys(request_ids))[:10],
        "correlation_ids": list(dict.fromkeys(correlation_ids))[:10],
    }


def _summarize_fix_verifications(rows: list[FixVerification]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for row in rows[:10]:
        summary.append(
            {
                "verification_status": row.verification_status.value,
                "checks_run_count": len(row.checks_run or []),
                "passed_checks_count": len(row.passed_checks or []),
                "failed_checks_count": len(row.failed_checks or []),
                "evidence_used_count": len(row.evidence_used or []),
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            }
        )
    return summary


def build_remediation_evidence_package(db: Session, incident_id: str) -> dict[str, Any]:
    """Return a masked, evidence-grounded package for problem-specific AI remediation."""
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    detections = list(
        db.scalars(
            select(Detection).where(Detection.incident_id == incident_id).order_by(Detection.id.asc())
        ).all()
    )
    alerts = list(
        db.scalars(
            select(PrivacyAlert)
            .where(PrivacyAlert.linked_incident_id == incident_id)
            .order_by(PrivacyAlert.alert_time.asc())
        ).all()
    )
    events = list(
        db.scalars(
            select(NormalizedEvent)
            .where(NormalizedEvent.linked_incident_id == incident_id)
            .order_by(NormalizedEvent.timestamp.asc())
        ).all()
    )
    evidence_files = list(
        db.scalars(
            select(EvidenceFile)
            .where(EvidenceFile.linked_incident_id == incident_id)
            .order_by(EvidenceFile.id.asc())
        ).all()
    )
    evidence_ids = [row.evidence_id for row in evidence_files]

    sast_findings: list[SastFinding] = []
    secret_findings: list[SecretFinding] = []
    if evidence_ids:
        sast_findings = list(
            db.scalars(select(SastFinding).where(SastFinding.evidence_id.in_(evidence_ids))).all()
        )
        secret_findings = list(
            db.scalars(select(SecretFinding).where(SecretFinding.evidence_id.in_(evidence_ids))).all()
        )

    cicd_evidence = list(
        db.scalars(
            select(CicdEvidence)
            .where(CicdEvidence.linked_incident_id == incident_id)
            .order_by(CicdEvidence.event_time.asc())
        ).all()
    )
    scanner_records = list(
        db.scalars(
            select(ScannerEvidenceRecord)
            .where(ScannerEvidenceRecord.linked_incident_id == incident_id)
            .order_by(ScannerEvidenceRecord.detected_at.asc())
        ).all()
    )
    fix_verifications = list(
        db.scalars(
            select(FixVerification)
            .where(FixVerification.incident_id == incident_id)
            .order_by(FixVerification.timestamp.desc(), FixVerification.id.desc())
        ).all()
    )

    scores = causality_engine.list_root_cause_scores(db, incident_id)
    top = _top_root_cause(scores)

    evidence_strength: dict[str, Any] | None = None
    try:
        evidence_strength = calculate_evidence_strength(db, incident_id)
    except Exception:
        evidence_strength = None

    sensitive_types = _collect_sensitive_types(detections, alerts)
    exposure_locations = _collect_exposure_locations(alerts)
    environments = list(
        dict.fromkeys(
            loc
            for loc in ([alert.environment for alert in alerts if alert.environment] + [None])
            if loc
        )
    )
    occurrence_count = max([alert.repeat_count for alert in alerts], default=0)

    masked_detections = [
        {
            "detection_id": row.detection_id,
            "sensitive_type": row.sensitive_type,
            "masked_value": _safe_text(row.masked_value),
            "severity": row.severity.value if row.severity else None,
            "detector_name": _safe_text(row.detector_name),
            "evidence_id": row.evidence_id,
        }
        for row in detections
        if not restricted_data_policy_service.is_restricted_category(
            row.sensitive_type, channel="external_ai"
        )
    ]

    masked_alerts = [
        {
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
            "source_type": alert.source_type,
            "source_name": _safe_text(alert.source_name),
            "service_name": _safe_text(alert.service_name),
            "endpoint": _safe_text(alert.endpoint),
            "environment": alert.environment,
            "exposure_location": alert.exposure_location,
            "sensitive_types": list(alert.sensitive_types or []),
            "masked_alert_summary": _safe_text(alert.alert_summary),
            "evidence_strength": alert.evidence_strength,
            "repeat_count": alert.repeat_count,
            "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
            "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
        }
        for alert in alerts
    ]

    package: dict[str, Any] = {
        "incident_id": incident.incident_id,
        "title": _safe_text(incident.title),
        "affected_service": _safe_text(incident.affected_service),
        "affected_endpoint": _safe_text(incident.affected_endpoint),
        "severity": incident.severity.value if incident.severity else None,
        "status": incident.status.value if incident.status else None,
        "safe_incident_summary": _safe_text(incident.summary),
        "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
        "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
        "occurrence_count": occurrence_count,
        "environment": environments[0] if environments else None,
        "environments": environments,
        "sensitive_types": sensitive_types,
        "exposure_locations": exposure_locations,
        "correlation_identifiers": _safe_correlation_ids(events),
        "masked_detections": masked_detections,
        "privacy_alerts": masked_alerts,
        "likely_root_cause": _safe_text(top.likely_root_cause if top else None),
        "root_cause_category": _safe_text(top.cause_name if top else None),
        "root_cause_analysis_id": top.analysis_id if top else None,
        "root_cause_confidence": top.confidence if top else None,
        "root_cause_confidence_band": _safe_text(top.confidence_band if top else None),
        "root_cause_stale": top.stale if top else None,
        "recommended_fix_summary": _safe_text(top.recommended_fix if top else None),
        "root_cause_explanation": _safe_text(top.explanation if top else None),
        "supporting_evidence_ids": list(top.supporting_evidence_ids or []) if top else [],
        "missing_evidence": [
            safe
            for item in (top.missing_evidence or [])
            if top and (safe := _safe_text(str(item)))
        ],
        "contradicting_evidence": list((top.contradicting_evidence or [])[:8]) if top else [],
        "negative_signals": list((top.negative_signals or [])[:8]) if top else [],
        "matched_signals": list((top.matched_signals or [])[:8]) if top else [],
        "causal_evidence_strength": (
            evidence_strength.get("causal_evidence_strength") if evidence_strength else None
        ),
        "post_remediation_validation": (
            evidence_strength.get("post_remediation_validation") if evidence_strength else None
        ),
        "evidence_strength_summary": {
            "confidence_level": evidence_strength.get("confidence_level") if evidence_strength else None,
            "confidence_score": evidence_strength.get("confidence_score") if evidence_strength else None,
            "evidence_strength_level": (
                evidence_strength.get("evidence_strength_level") if evidence_strength else None
            ),
            "supporting_evidence": (
                evidence_strength.get("supporting_evidence", [])[:10] if evidence_strength else []
            ),
            "contradicting_evidence": (
                evidence_strength.get("contradicting_evidence", [])[:8] if evidence_strength else []
            ),
            "missing_evidence": evidence_strength.get("missing_evidence", []) if evidence_strength else [],
            "limitations": evidence_strength.get("limitations", []) if evidence_strength else [],
        },
        "deployment_evidence": [
            {
                "cicd_evidence_id": row.cicd_evidence_id,
                "evidence_type": row.evidence_type,
                "service_name": _safe_text(row.service_name),
                "deployment_version": _safe_text(row.deployment_version),
                "commit_reference": _safe_text(row.commit_reference),
                "changed_file_paths_safe": list(row.changed_file_paths_safe or [])[:20],
                "change_categories": list(row.change_categories or [])[:10],
                "scan_summary_safe": _safe_text(row.scan_summary_safe),
                "test_summary_safe": _safe_text(row.test_summary_safe),
                "event_time": row.event_time.isoformat() if row.event_time else None,
            }
            for row in cicd_evidence
        ],
        "scanner_findings": [
            {
                "scanner_evidence_id": row.scanner_evidence_id,
                "source_format": row.source_format,
                "finding_type": _safe_text(row.finding_type),
                "source_file": _safe_text(row.source_file),
                "line_number": row.line_number,
                "repository": _safe_text(row.repository),
                "masked_value": _safe_text(row.masked_value),
                "explanation": _safe_text(row.explanation),
                "evidence_reference": row.evidence_reference,
            }
            for row in scanner_records
        ],
        "sast_findings": [
            {
                "evidence_id": row.evidence_id,
                "rule_id": _safe_text(row.rule_id),
                "file_path": _safe_text(row.file_path),
                "line_number": row.line_number,
                "finding_type": _safe_text(row.finding_type),
                "message": _safe_text(row.message),
                "severity": row.severity.value if row.severity else None,
            }
            for row in sast_findings
        ],
        "secret_findings": [
            {
                "evidence_id": row.evidence_id,
                "secret_type": _safe_text(row.secret_type),
                "file_path": _safe_text(row.file_path),
                "masked_secret": _safe_text(row.masked_secret),
                "severity": row.severity.value if row.severity else None,
            }
            for row in secret_findings
        ],
        "fix_verification_summary": _summarize_fix_verifications(fix_verifications),
        "limitations": [
            "Package contains masked summaries only; raw sensitive values are excluded.",
            "Likely root cause is rule-ranked supporting evidence, not proven causation.",
        ],
    }

    if top and top.stale:
        package["limitations"].append(
            "Root-cause analysis batch is marked stale; regenerate analysis before relying on rankings."
        )

    package, _restricted = restricted_data_policy_service.sanitize_payload(
        package,
        channel="external_ai",
    )
    return package
