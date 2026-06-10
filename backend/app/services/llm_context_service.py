"""Build masked LLM context from Phase 6 outputs (Guarded LLM Investigation Assistant)."""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Detection, EvidenceFile, Incident, NormalizedEvent
from app.services import causality_engine, restricted_data_policy_service


def build_llm_context(db: Session, incident_id: str) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise KeyError(f"Incident not found: {incident_id}")

    # Phase N: only the incident's current (latest) analysis version should
    # feed the guarded LLM investigation context.
    scores = causality_engine.list_root_cause_scores(db, incident_id)
    detections = list(
        db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    )
    events = list(
        db.scalars(
            select(NormalizedEvent)
            .where(NormalizedEvent.linked_incident_id == incident_id)
            .order_by(NormalizedEvent.timestamp, NormalizedEvent.id)
        ).all()
    )
    evidence_ids = {e.evidence_id for e in events} | {
        d.evidence_id for d in detections if d.evidence_id
    }
    evidence_files: list[EvidenceFile] = []
    if evidence_ids:
        evidence_files = list(
            db.scalars(
                select(EvidenceFile).where(EvidenceFile.evidence_id.in_(evidence_ids))
            ).all()
        )

    events_by_evidence: dict[str, list[NormalizedEvent]] = {}
    for ev in events:
        events_by_evidence.setdefault(ev.evidence_id, []).append(ev)

    masked_evidence = []
    for ef in evidence_files:
        evs = events_by_evidence.get(ef.evidence_id, [])
        sample = evs[0] if evs else None
        masked_evidence.append(
            {
                "evidence_id": ef.evidence_id,
                "source_type": ef.evidence_type.value,
                "endpoint": sample.endpoint if sample else incident.affected_endpoint,
                "service_name": sample.service_name if sample else incident.affected_service,
                "masked_message": sample.masked_message if sample and sample.masked_message else "",
            }
        )

    root_cause_ranking = [
        {
            "rank": s.rank,
            "cause_name": s.likely_root_cause,
            "likely_root_cause": s.likely_root_cause,
            "confidence": s.confidence,
            "confidence_band": s.confidence_band,
            "supporting_evidence_ids": s.supporting_evidence_ids or [],
            "missing_evidence": s.missing_evidence or [],
            "recommended_fix": (s.recommended_fix or "").strip(),
        }
        for s in scores
    ]

    masked_detection_summary = [
        {
            "detection_id": d.detection_id,
            "sensitive_type": d.sensitive_type,
            "masked_value": d.masked_value,
            "evidence_id": d.evidence_id,
        }
        for d in detections
    ]

    context = {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "affected_endpoint": incident.affected_endpoint,
        "affected_service": incident.affected_service,
        "status": incident.status.value,
        "severity": incident.severity.value,
        "root_cause_ranking": root_cause_ranking,
        "masked_evidence": masked_evidence,
        "masked_detection_summary": masked_detection_summary,
        "rules": {
            "must_use_evidence_ids": True,
            "must_not_claim_certainty": True,
            "human_review_required": True,
            "raw_sensitive_values_forbidden": True,
        },
    }
    context, _restricted_present = restricted_data_policy_service.sanitize_payload(
        context,
        channel="external_ai",
    )
    return context


def hash_context(context: dict) -> str:
    payload = json.dumps(context, sort_keys=True, default=str)
    return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def collect_known_evidence_ids(context: dict) -> set[str]:
    ids: set[str] = set()
    for item in context.get("masked_evidence") or []:
        eid = item.get("evidence_id")
        if eid:
            ids.add(str(eid))
    for rank in context.get("root_cause_ranking") or []:
        for eid in rank.get("supporting_evidence_ids") or []:
            ids.add(str(eid))
    for det in context.get("masked_detection_summary") or []:
        eid = det.get("evidence_id")
        if eid:
            ids.add(str(eid))
    return ids
