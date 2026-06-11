"""Causal relevance scoring for scanner evidence vs incidents."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.scanner_evidence_record import ScannerEvidenceRecord
from app.schemas.scanner_evidence_schema import (
    ScannerCorrelationItem,
    ScannerCorrelationResponse,
)

CORRELATION_SUMMARY = (
    "Scanner evidence contributes supporting evidence for investigation; "
    "it does not prove root cause. Human review is required."
)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def compute_causal_relevance(
    record: ScannerEvidenceRecord,
    incident: Incident | None,
) -> float:
    score = 0.0
    verified = (record.verification_status or "").lower() == "verified"
    if verified:
        score += 0.30
    else:
        score += 0.15

    sev = record.severity.value if record.severity else None
    if sev in ("critical", "high"):
        score += 0.20
    elif sev == "medium":
        score += 0.10

    if incident:
        if record.service_hint and incident.affected_service:
            if record.service_hint.lower() in incident.affected_service.lower() or (
                incident.affected_service.lower() in record.service_hint.lower()
            ):
                score += 0.20
        if record.source_file and incident.affected_service:
            if incident.affected_service.lower().replace("-", "_") in (
                record.source_file or ""
            ).lower():
                score += 0.15
        if record.endpoint_hint and incident.affected_endpoint:
            if record.endpoint_hint.lower() in incident.affected_endpoint.lower():
                score += 0.20
        if record.linked_incident_id:
            score += 0.05
    else:
        score -= 0.10

    path = (record.source_file or "").lower()
    if any(x in path for x in ("test", "fixture", "mock", "__tests__")):
        score -= 0.20
    if sev == "low":
        score -= 0.10
    if not record.linked_incident_id:
        score -= 0.10

    auth_hints = ("auth", "config", "logging", "env", "secret")
    if any(h in path for h in auth_hints):
        score += 0.15

    return _clamp01(score)


def bucket(score: float) -> str:
    if score >= 0.75:
        return "strong"
    if score >= 0.45:
        return "moderate"
    return "weak"


def correlate_incident(
    db: Session,
    incident_id: str,
) -> ScannerCorrelationResponse:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    records = list(
        db.scalars(
            select(ScannerEvidenceRecord).where(
                ScannerEvidenceRecord.linked_incident_id == incident_id
            )
        ).all()
    )

    strong: list[ScannerCorrelationItem] = []
    moderate: list[ScannerCorrelationItem] = []
    weak: list[ScannerCorrelationItem] = []
    missing: list[str] = []

    if incident is None:
        missing.append("incident_not_found")
    if not records:
        missing.append("no_scanner_evidence_imported")

    scored: list[tuple[ScannerEvidenceRecord, float]] = []
    for rec in records:
        score = compute_causal_relevance(rec, incident)
        rec.causal_relevance_score = score
        scored.append((rec, score))

    scored.sort(key=lambda x: x[1], reverse=True)

    for rec, score in scored:
        item = ScannerCorrelationItem(
            scanner_evidence_id=rec.scanner_evidence_id,
            causal_relevance_score=score,
            detector_name=rec.detector_name,
            masked_value=rec.masked_value,
            source_file=rec.source_file,
            explanation=rec.explanation,
        )
        b = bucket(score)
        if b == "strong":
            strong.append(item)
        elif b == "moderate":
            moderate.append(item)
        else:
            weak.append(item)

    db.flush()
    top = [item for rec, score in scored[:5] for item in [
        ScannerCorrelationItem(
            scanner_evidence_id=rec.scanner_evidence_id,
            causal_relevance_score=score,
            detector_name=rec.detector_name,
            masked_value=rec.masked_value,
            source_file=rec.source_file,
            explanation=rec.explanation,
        )
    ]]

    if incident and not incident.affected_service:
        missing.append("incident_missing_affected_service")
    if incident and not incident.affected_endpoint:
        missing.append("incident_missing_affected_endpoint")

    return ScannerCorrelationResponse(
        incident_id=incident_id,
        scanner_evidence_count=len(records),
        strong_supporting_evidence=strong,
        moderate_supporting_evidence=moderate,
        weak_supporting_evidence=weak,
        top_scanner_evidence=top,
        missing_context=missing,
        human_review_required=True,
        summary=CORRELATION_SUMMARY,
    )
