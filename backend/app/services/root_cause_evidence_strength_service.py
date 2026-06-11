"""Authoritative evidence-strength calculation (Phase M).

Splits the previously mixed "evidence strength" concept into two distinct,
separately-scored ideas:

* `compute_causal_evidence_strength` — how strong the *pre-remediation*
  technical case for a likely root cause is. Only structured exposure facts,
  trace/deployment/scanner correlation, symptom/timeline evidence, and
  contradictions may move this score. Human review approval, remediation
  completion, retest evidence, and fix-verification results are never read
  by this function, so a later successful fix can never retroactively
  inflate (or a failed one deflate) the causal record of what the evidence
  looked like at analysis time.
* `compute_post_remediation_validation` — a separate score/status for what
  happened *after* a cause was identified: remediation recorded, retested,
  verified, human-approved. This is allowed to use exactly the signals the
  causal function must not.

Both are pure functions of an input dataclass (`CausalEvidenceInputs` /
`ValidationInputs`) with no database access, so they can be unit-tested with
plain mock objects. `compute_causal_evidence_strength(db, incident_id)` and
`compute_post_remediation_validation(db, incident_id)` are thin DB-fetching
wrappers around them. `calculate_evidence_strength(db, incident_id)` remains
the single combined entry point existing routers/services already call; it
now sources its top-level `evidence_strength_*`/`confidence_*` fields from
the causal result only (never inflated by remediation), and additionally
exposes both `causal_evidence_strength` and `post_remediation_validation` as
nested, independently-inspectable fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.cicd_evidence import CicdEvidence
from app.models.deployment_event import DeploymentEvent
from app.models.detection import Detection
from app.models.enums import EvidenceType, ReviewDecisionType, VerificationStatus
from app.models.evidence_file import EvidenceFile
from app.models.fix_verification import FixVerification
from app.models.incident import Incident
from app.models.normalized_event import NormalizedEvent
from app.models.privacy_alert import PrivacyAlert
from app.models.remediation_action import RemediationAction
from app.models.review_decision import ReviewDecision
from app.models.root_cause_score import RootCauseScore
from app.models.sast_finding import SastFinding
from app.models.scanner_evidence_record import ScannerEvidenceRecord
from app.services import audit_safety_service
from app.services.remediation_action_service import remediation_is_complete


FORBIDDEN_REPLACEMENTS = {
    "proven root cause": "likely cause",
    "proven cause": "likely cause",
    "confirmed cause": "likely cause",
    "confirmed blame": "likely contribution",
    "developer fault": "application contribution",
    "guaranteed cause": "likely cause",
    "guaranteed fixed": "verification result",
    "confirmed breach": "privacy incident",
    "confirmed bola": "possible authorization issue",
    "confirmed idor": "possible authorization issue",
    "attacker accessed data": "access requires further evidence",
    "ai solved the issue": "AI suggestion requires human review",
    "incident closed automatically": "incident requires human disposition",
    "siem replacement": "supporting monitoring integration",
}
TECHNICAL_CICD_TYPES = {
    "deployment_event",
    "changed_files",
    "security_scan_result",
    "configuration_change",
    "rollback_event",
    "release_metadata",
}
RETEST_TYPES = {EvidenceType.FIXED_LOG, EvidenceType.FIXED_SCAN}


class RootCauseEvidenceStrengthError(Exception):
    pass


class IncidentNotFoundError(RootCauseEvidenceStrengthError):
    pass


def _safe_text(value: Any, fallback: str = "Evidence detail available.") -> str:
    text = str(value or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    for phrase, replacement in FORBIDDEN_REPLACEMENTS.items():
        if phrase in lowered:
            start = lowered.index(phrase)
            text = text[:start] + replacement + text[start + len(phrase) :]
            lowered = text.lower()
    return audit_safety_service.mask_sensitive_text(text)


def _safe_signal(item: Any) -> dict:
    if not isinstance(item, dict):
        return {"reason": _safe_text(item)}
    allowed = {
        "signal_name",
        "match_type",
        "matched",
        "weight",
        "evidence_ids",
        "reason",
        "time_context",
        "is_negative",
        "is_contradiction",
    }
    result: dict = {}
    for key, value in item.items():
        if key not in allowed:
            continue
        if isinstance(value, str):
            result[key] = _safe_text(value)
        elif isinstance(value, list):
            result[key] = [_safe_text(v) if isinstance(v, str) else v for v in value]
        elif isinstance(value, dict):
            result[key] = {str(k): _safe_text(v) for k, v in value.items()}
        else:
            result[key] = value
    return result


def _confidence_label(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.7:
        return "medium-high"
    if score >= 0.45:
        return "medium"
    return "low"


def _support_item(
    evidence_id: str,
    evidence_type: str,
    role: str,
    summary: str,
    reason: str,
    *,
    source: str | None = None,
    event_time: datetime | None = None,
) -> dict:
    return {
        "evidence_id": evidence_id,
        "evidence_type": evidence_type,
        "evidence_role": role,
        "safe_summary": _safe_text(summary),
        "support_reason": _safe_text(reason),
        "source": _safe_text(source, "") or None,
        "event_time": event_time,
    }


# --------------------------------------------------------------------------
# Phase M: pure input containers (no I/O) — every field here is exactly what
# each pure scoring function is allowed to read, which is what keeps the
# causal/validation split enforceable rather than just documented.
# --------------------------------------------------------------------------


@dataclass
class CausalEvidenceInputs:
    incident: Any
    alerts: list = field(default_factory=list)
    detections: list = field(default_factory=list)
    evidence_files: list = field(default_factory=list)
    events: list = field(default_factory=list)
    scanners: list = field(default_factory=list)
    cicd: list = field(default_factory=list)
    deployments: list = field(default_factory=list)
    sast_count: int = 0
    top_root_cause: Any | None = None


@dataclass
class ValidationInputs:
    incident: Any
    remediation_actions: list = field(default_factory=list)
    review: Any | None = None
    verification: Any | None = None
    events: list = field(default_factory=list)
    evidence_files: list = field(default_factory=list)
    cicd: list = field(default_factory=list)
    top_root_cause: Any | None = None


def _strong_scanners(scanners: list, incident: Any) -> list:
    return [
        item
        for item in scanners
        if (getattr(item, "causal_relevance_score", None) or getattr(item, "confidence", None) or 0) >= 0.6
        and (
            not getattr(incident, "affected_service", None)
            or not getattr(item, "service_hint", None)
            or item.service_hint.lower() == incident.affected_service.lower()
        )
    ]


# --------------------------------------------------------------------------
# Phase M(1): causal evidence strength — pre-remediation technical case only.
# --------------------------------------------------------------------------


def compute_causal_evidence_strength_from_context(ctx: CausalEvidenceInputs) -> dict:
    """Score how strong the pre-remediation technical case is.

    MUST NOT read (and does not accept) remediation, retest, verification, or
    human-review state — see module docstring.
    """
    incident = ctx.incident
    top = ctx.top_root_cause

    symptom_files = [
        item
        for item in ctx.evidence_files
        if item.evidence_type in {EvidenceType.API_LOG, EvidenceType.RUNTIME_LOG, EvidenceType.SIEM_ALERT}
    ]
    technical_cicd = [item for item in ctx.cicd if item.evidence_type in TECHNICAL_CICD_TYPES]
    strong_scanners = _strong_scanners(ctx.scanners, incident)

    symptom_count = len(ctx.alerts) + len(ctx.detections) + len(symptom_files)
    timeline_count = (
        len([item for item in ctx.alerts if item.alert_time])
        + len([item for item in ctx.events if item.timestamp])
        + len([item for item in ctx.cicd if item.event_time])
        + len([item for item in ctx.deployments if item.deployment_time])
    )
    technical_count = len(technical_cicd) + len(ctx.deployments) + len(strong_scanners) + ctx.sast_count

    contradictions = list(top.contradicting_evidence or []) if top else []
    missing: list[str] = [
        item
        for item in (list(top.missing_evidence or []) if top else [])
        if "retest" not in item.lower()
    ]
    if not incident.affected_service:
        missing.append("Affected service metadata is missing.")
    if not incident.affected_endpoint:
        missing.append("Affected endpoint metadata is missing.")
    if not incident.first_seen and not any(item.alert_time for item in ctx.alerts):
        missing.append("Reliable event time is missing.")
    if technical_count == 0:
        missing.append("Technical deployment, configuration, changed-file, or scanner evidence is missing.")
    missing = list(dict.fromkeys(_safe_text(item) for item in missing if item))

    score = 0.0
    if symptom_count:
        score += 0.18 + min(0.12, max(0, symptom_count - 1) * 0.03)
    if timeline_count:
        score += min(0.12, 0.04 + timeline_count * 0.015)
    if incident.affected_service and incident.affected_endpoint:
        score += 0.08
    if technical_count:
        score += min(0.34, 0.2 + technical_count * 0.035)
    score -= min(0.3, len(contradictions) * 0.1)
    if not incident.affected_service:
        score -= 0.08
    if not incident.affected_endpoint:
        score -= 0.08
    if not incident.first_seen and not ctx.alerts:
        score -= 0.06
    score = round(max(0.0, min(1.0, score)), 3)

    # "very strong" is achievable purely technically: several independent
    # technical evidence sources, no unresolved contradictions, and complete
    # service/endpoint/time context — never via remediation/review/retest.
    context_complete = bool(
        incident.affected_service and incident.affected_endpoint and (incident.first_seen or ctx.alerts)
    )
    independent_technical_sources = sum(
        1
        for count in (len(technical_cicd), len(ctx.deployments), len(strong_scanners), ctx.sast_count)
        if count
    )
    very_strong_causal_allowed = bool(
        independent_technical_sources >= 2 and not contradictions and context_complete
    )

    if very_strong_causal_allowed and score >= 0.72:
        strength = "very_strong"
        reason = (
            "Multiple independent technical evidence sources (deployment, configuration, or "
            "scanner) corroborate the symptom and timeline correlation without contradiction."
        )
    elif technical_count and score >= 0.5:
        strength = "strong"
        reason = "Linked technical evidence strengthens the symptom and timeline correlation."
    elif symptom_count >= 2 or score >= 0.3:
        strength = "medium"
        reason = "Multiple correlated observations support the likely cause, but technical confirmation is limited."
    else:
        strength = "weak"
        reason = "Current evidence is primarily a single symptom source or lacks key context."

    if very_strong_causal_allowed:
        cap_score = 0.92
        cap_reason = "High confidence is allowed because multiple independent technical sources corroborate this cause."
    elif technical_count:
        cap_score = 0.85
        cap_reason = "Technical evidence allows a high confidence cap, subject to missing and contradicting evidence."
    elif symptom_count >= 2 and context_complete:
        cap_score = 0.72
        cap_reason = "Multiple correlated symptom sources are capped at medium-high without technical evidence."
    else:
        cap_score = 0.6
        cap_reason = "Live alerts or uploaded logs alone are capped at medium confidence."
    if not incident.affected_service:
        cap_score -= 0.1
        cap_reason += " Missing service metadata reduces the cap."
    if not incident.affected_endpoint:
        cap_score -= 0.1
        cap_reason += " Missing endpoint metadata reduces the cap."
    if not incident.first_seen and not ctx.alerts:
        cap_score -= 0.08
        cap_reason += " Missing event time reduces timeline confidence."
    if contradictions:
        cap_score -= min(0.25, 0.1 * len(contradictions))
        cap_reason += " Contradicting evidence reduces the cap."
    cap_score = round(max(0.2, min(0.92, cap_score)), 3)

    candidate_confidence = float(top.confidence or score) if top else score
    causal_score = round(max(0.0, min(candidate_confidence, score or candidate_confidence, cap_score)), 3)
    causal_level = _confidence_label(causal_score)
    cap_label = _confidence_label(cap_score)

    support: list[dict] = []
    for item in technical_cicd:
        support.append(
            _support_item(
                item.cicd_evidence_id,
                item.evidence_type,
                "technical_cause",
                item.scan_summary_safe or item.test_summary_safe or "Structured CI/CD evidence is linked.",
                "Provides deployment, configuration, changed-file, scan, or release context.",
                source=item.source_name,
                event_time=item.event_time,
            )
        )
    for item in strong_scanners:
        support.append(
            _support_item(
                item.scanner_evidence_id,
                item.source_format,
                "technical_cause",
                item.explanation or item.finding_type or "Linked scanner evidence.",
                "Scanner evidence is linked to the affected component; it remains supporting evidence.",
                source=item.detector_name,
                event_time=item.detected_at,
            )
        )
    for item in ctx.alerts:
        support.append(
            _support_item(
                item.alert_id,
                "privacy_alert",
                "symptom",
                f"Masked alert for {', '.join(item.sensitive_types or ['sensitive data'])}.",
                "Shows the privacy symptom observed by the live monitor.",
                source=item.source_name or item.source_type,
                event_time=item.alert_time,
            )
        )
    for item in ctx.events[:5]:
        support.append(
            _support_item(
                item.event_id,
                item.source_type,
                "timeline",
                item.masked_message or "Masked event metadata is linked.",
                "Provides service, endpoint, release, or timing correlation.",
                source=item.source_type,
                event_time=item.timestamp,
            )
        )
    for item in ctx.detections[:5]:
        support.append(
            _support_item(
                item.detection_id,
                item.sensitive_type,
                "symptom",
                f"Masked detection: {item.masked_value}",
                "Shows the detected sensitive-data category without exposing the raw value.",
                source=item.detector_name,
                event_time=item.created_at,
            )
        )

    contradiction_items = [
        _support_item(
            str(item.get("evidence_id") or f"CONTRA-{index + 1}"),
            "contradicting_evidence",
            "contradiction",
            item.get("reason") or "Contradicting evidence was recorded.",
            "Reduces causal confidence and requires human review.",
        )
        for index, item in enumerate(contradictions)
        if isinstance(item, dict)
    ]

    recommended = []
    for item in missing[:5]:
        if "service" in item.lower() or "endpoint" in item.lower():
            recommended.append("Add safe service and endpoint metadata.")
        elif "technical" in item.lower():
            recommended.append("Link deployment, configuration, changed-file, or relevant scanner evidence.")
        else:
            recommended.append(f"Collect supporting evidence: {item}")
    recommended = list(dict.fromkeys(recommended))[:5]

    limitations = [
        "The result ranks a likely cause from pre-remediation technical evidence and does not "
        "establish certainty.",
        "Human review is required before remediation or incident disposition.",
        "This score deliberately excludes remediation, retest, verification, and review outcomes; "
        "see post_remediation_validation for those.",
    ]
    if cap_score < 0.85:
        limitations.append(cap_reason)
    if contradictions:
        limitations.append("Contradicting evidence remains unresolved.")

    return {
        "incident_id": getattr(incident, "incident_id", None),
        "likely_root_cause": _safe_text(top.likely_root_cause, "") or None if top else None,
        "root_cause_category": _safe_text(top.cause_name, "") or None if top else None,
        "causal_confidence_level": causal_level,
        "causal_confidence_score": causal_score,
        "causal_strength_level": strength,
        "causal_strength_score": score,
        "causal_strength_reason": reason,
        "causal_confidence_cap": cap_label,
        "causal_confidence_cap_score": cap_score,
        "causal_confidence_cap_reason": cap_reason,
        "supporting_evidence": support,
        "contradicting_evidence": contradiction_items,
        "symptom_evidence_count": symptom_count,
        "timeline_evidence_count": timeline_count,
        "technical_evidence_count": technical_count,
        "matched_signals": [_safe_signal(item) for item in (top.matched_signals or [])] if top else [],
        "negative_signals": [_safe_signal(item) for item in (top.negative_signals or [])] if top else [],
        "contradiction_signals": [_safe_signal(item) for item in contradictions],
        "missing_evidence": missing,
        "recommended_next_evidence": recommended,
        "excludes_post_remediation_evidence": True,
        "limitations": limitations,
    }


def _fetch_causal_inputs(db: Session, incident_id: str, *, incident: Incident) -> CausalEvidenceInputs:
    alerts = list(
        db.scalars(select(PrivacyAlert).where(PrivacyAlert.linked_incident_id == incident_id)).all()
    )
    detections = list(
        db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    )
    evidence_files = list(
        db.scalars(select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)).all()
    )
    events = list(
        db.scalars(select(NormalizedEvent).where(NormalizedEvent.linked_incident_id == incident_id)).all()
    )
    scanners = list(
        db.scalars(
            select(ScannerEvidenceRecord).where(
                ScannerEvidenceRecord.linked_incident_id == incident_id
            )
        ).all()
    )
    cicd = list(
        db.scalars(select(CicdEvidence).where(CicdEvidence.linked_incident_id == incident_id)).all()
    )
    deployments = list(
        db.scalars(
            select(DeploymentEvent)
            .join(EvidenceFile, DeploymentEvent.evidence_id == EvidenceFile.evidence_id)
            .where(EvidenceFile.linked_incident_id == incident_id)
        ).all()
    )
    sast_count = len(
        list(
            db.scalars(
                select(SastFinding)
                .join(EvidenceFile, SastFinding.evidence_id == EvidenceFile.evidence_id)
                .where(EvidenceFile.linked_incident_id == incident_id)
            ).all()
        )
    )
    top = _top_root_cause(db, incident_id)
    return CausalEvidenceInputs(
        incident=incident,
        alerts=alerts,
        detections=detections,
        evidence_files=evidence_files,
        events=events,
        scanners=scanners,
        cicd=cicd,
        deployments=deployments,
        sast_count=sast_count,
        top_root_cause=top,
    )


def compute_causal_evidence_strength(db: Session, incident_id: str) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    ctx = _fetch_causal_inputs(db, incident_id, incident=incident)
    return compute_causal_evidence_strength_from_context(ctx)


# --------------------------------------------------------------------------
# Phase M(2): post-remediation validation — remediation/retest/verification/
# review only. Never used to compute causal strength above.
# --------------------------------------------------------------------------


def compute_post_remediation_validation_from_context(ctx: ValidationInputs) -> dict:
    incident = ctx.incident
    top = ctx.top_root_cause

    retest_files = [item for item in ctx.evidence_files if item.evidence_type in RETEST_TYPES]
    complete_remediation = [item for item in ctx.remediation_actions if remediation_is_complete(item)]
    remediation_count = len(complete_remediation)
    verification_count = 1 if ctx.verification is not None else 0

    approved = bool(ctx.review and ctx.review.decision == ReviewDecisionType.APPROVED.value)
    verification_passed = bool(
        ctx.verification and ctx.verification.verification_status == VerificationStatus.PASSED
    )
    verification_failed = bool(
        ctx.verification and ctx.verification.verification_status != VerificationStatus.PASSED
    )
    retest_event_ids = {item.evidence_id for item in retest_files}
    retest_events = [item for item in ctx.events if item.evidence_id in retest_event_ids]
    matching_retest = any(
        (not incident.affected_service or event.service_name == incident.affected_service)
        and (not incident.affected_endpoint or event.endpoint == incident.affected_endpoint)
        for event in retest_events
    ) or any(
        item.evidence_type == "test_result"
        and (not incident.affected_service or item.service_name == incident.affected_service)
        for item in ctx.cicd
    )
    cause_text = " ".join(
        [top.likely_root_cause if top else "", incident.affected_service or ""]
    ).lower().replace("_", " ")
    cause_tokens = {token for token in cause_text.split() if len(token) > 3}
    matching_remediation = any(
        cause_tokens.intersection(action.affected_component.lower().replace("_", " ").split())
        for action in complete_remediation
    )

    if verification_passed:
        status = "verified_passed"
        reason = "A fix verification with a passed status is linked to this incident."
    elif verification_failed:
        status = "verified_failed"
        reason = "A fix verification is linked, but its result was not a pass."
    elif retest_files or matching_retest:
        status = "retested"
        reason = "Retest evidence is linked but has not produced a formal pass/fail verification result yet."
    elif remediation_count:
        status = "remediation_recorded"
        reason = "A human-saved remediation action is recorded, but no retest or verification evidence is linked yet."
    else:
        status = "not_started"
        reason = "No remediation, retest, or verification evidence is linked to this incident yet."

    validation_score = 0.0
    if remediation_count:
        validation_score += 0.35
    if matching_remediation:
        validation_score += 0.15
    if matching_retest:
        validation_score += 0.2
    if verification_passed:
        validation_score += 0.2
    if verification_failed:
        validation_score -= 0.15
    if approved:
        validation_score += 0.1
    validation_score = round(max(0.0, min(1.0, validation_score)), 3)

    missing: list[str] = []
    if remediation_count == 0:
        missing.append("A human-saved remediation action is missing.")
    elif not (retest_files or matching_retest):
        missing.append("Retest evidence is missing.")
    elif verification_count == 0:
        missing.append("A formal fix verification result is missing.")
    if not approved:
        missing.append("Human review approval is missing.")
    missing = list(dict.fromkeys(_safe_text(item) for item in missing if item))

    support: list[dict] = []
    for item in complete_remediation:
        support.append(
            _support_item(
                item.remediation_action_id,
                item.action_type,
                "remediation",
                item.action_description,
                "Records the human-saved action used for downstream retest comparison.",
                source=item.assigned_owner,
                event_time=item.updated_at,
            )
        )
    if ctx.verification:
        support.append(
            _support_item(
                f"VER-{getattr(ctx.verification, 'id', 'unknown')}",
                "fix_verification",
                "verification",
                f"Verification result: {ctx.verification.verification_status.value}.",
                "Summarises the result based on the available linked retest evidence.",
                event_time=ctx.verification.timestamp,
            )
        )

    limitations = [
        "This result reflects remediation/retest/verification/review state only; it never changes "
        "the pre-remediation causal record — see causal_evidence_strength for that.",
        "Human disposition is still required regardless of verification outcome.",
    ]

    return {
        "incident_id": getattr(incident, "incident_id", None),
        "validation_status": status,
        "validation_status_reason": _safe_text(reason),
        "validation_score": validation_score,
        "remediation_evidence_count": remediation_count,
        "verification_evidence_count": verification_count,
        "remediation_matches_cause": matching_remediation,
        "retest_matches_cause": matching_retest,
        "verification_passed": verification_passed,
        "verification_failed": verification_failed,
        "review_approved": approved,
        "human_review_required": not approved,
        "supporting_evidence": support,
        "missing_evidence": missing,
        "limitations": limitations,
    }


def _fetch_validation_inputs(db: Session, incident_id: str, *, incident: Incident) -> ValidationInputs:
    remediation_actions = list(
        db.scalars(
            select(RemediationAction).where(RemediationAction.incident_id == incident_id)
        ).all()
    )
    review = _latest_review(db, incident_id)
    verification = _latest_verification(db, incident_id)
    events = list(
        db.scalars(select(NormalizedEvent).where(NormalizedEvent.linked_incident_id == incident_id)).all()
    )
    evidence_files = list(
        db.scalars(select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)).all()
    )
    cicd = list(
        db.scalars(select(CicdEvidence).where(CicdEvidence.linked_incident_id == incident_id)).all()
    )
    top = _top_root_cause(db, incident_id)
    return ValidationInputs(
        incident=incident,
        remediation_actions=remediation_actions,
        review=review,
        verification=verification,
        events=events,
        evidence_files=evidence_files,
        cicd=cicd,
        top_root_cause=top,
    )


def compute_post_remediation_validation(db: Session, incident_id: str) -> dict:
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    ctx = _fetch_validation_inputs(db, incident_id, incident=incident)
    return compute_post_remediation_validation_from_context(ctx)


def _latest_review(db: Session, incident_id: str) -> ReviewDecision | None:
    return db.scalar(
        select(ReviewDecision)
        .where(ReviewDecision.incident_id == incident_id)
        .order_by(ReviewDecision.timestamp.desc(), ReviewDecision.id.desc())
        .limit(1)
    )


def _latest_verification(db: Session, incident_id: str) -> FixVerification | None:
    return db.scalar(
        select(FixVerification)
        .where(FixVerification.incident_id == incident_id)
        .order_by(FixVerification.timestamp.desc(), FixVerification.id.desc())
        .limit(1)
    )


def _top_root_cause(db: Session, incident_id: str) -> RootCauseScore | None:
    # Phase N: only ever consider the current (latest analysis_version)
    # batch — a superseded/stale historical row must never be treated as
    # "the" top likely cause.
    from app.services import causality_engine

    rows = causality_engine.list_root_cause_scores(db, incident_id)
    if not rows:
        return None
    ranked = sorted(
        rows,
        key=lambda row: (row.rank if row.rank is not None else 10_000, -(row.confidence or 0.0)),
    )
    return ranked[0]


# --------------------------------------------------------------------------
# Combined, backward-compatible entry point.
# --------------------------------------------------------------------------


def calculate_evidence_strength(db: Session, incident_id: str) -> dict:
    """Combined view used by existing routers/report services.

    Top-level `evidence_strength_*`/`confidence_*` fields are sourced from
    the causal result only (Phase M requirement 3: remediation success never
    rewrites historical causal strength). `causal_evidence_strength` and
    `post_remediation_validation` are also exposed in full so callers that
    need the distinction can use it directly (Phase M requirement 4).
    """
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")

    causal_ctx = _fetch_causal_inputs(db, incident_id, incident=incident)
    validation_ctx = _fetch_validation_inputs(db, incident_id, incident=incident)
    causal = compute_causal_evidence_strength_from_context(causal_ctx)
    validation = compute_post_remediation_validation_from_context(validation_ctx)

    missing = list(
        dict.fromkeys(list(causal["missing_evidence"]) + list(validation["missing_evidence"]))
    )
    recommended = list(causal["recommended_next_evidence"])
    for item in validation["missing_evidence"]:
        if "remediation" in item.lower():
            recommended.append("Record a human-saved remediation action.")
        elif "retest" in item.lower():
            recommended.append("Add masked retest evidence for the affected service and endpoint.")
        elif "verification" in item.lower():
            recommended.append("Run a formal fix verification once retest evidence is available.")
        elif "review" in item.lower():
            recommended.append("Ask a security analyst to review the likely cause and supporting evidence.")
    recommended = list(dict.fromkeys(recommended))[:5]

    return {
        "incident_id": incident_id,
        "likely_root_cause": causal["likely_root_cause"],
        "root_cause_category": causal["root_cause_category"],
        "confidence_level": causal["causal_confidence_level"],
        "confidence_score": causal["causal_confidence_score"],
        "evidence_strength_level": causal["causal_strength_level"],
        "evidence_strength_score": causal["causal_strength_score"],
        "evidence_strength_reason": causal["causal_strength_reason"],
        "confidence_cap": causal["causal_confidence_cap"],
        "confidence_cap_score": causal["causal_confidence_cap_score"],
        "confidence_cap_reason": causal["causal_confidence_cap_reason"],
        "supporting_evidence": list(causal["supporting_evidence"]) + list(validation["supporting_evidence"]),
        "contradicting_evidence": causal["contradicting_evidence"],
        "symptom_evidence_count": causal["symptom_evidence_count"],
        "timeline_evidence_count": causal["timeline_evidence_count"],
        "technical_evidence_count": causal["technical_evidence_count"],
        "remediation_evidence_count": validation["remediation_evidence_count"],
        "verification_evidence_count": validation["verification_evidence_count"],
        "matched_signals": causal["matched_signals"],
        "negative_signals": causal["negative_signals"],
        "contradiction_signals": causal["contradiction_signals"],
        "missing_evidence": missing,
        "recommended_next_evidence": recommended,
        "human_review_required": validation["human_review_required"],
        "limitations": list(causal["limitations"]) + list(validation["limitations"]),
        "causal_evidence_strength": causal,
        "post_remediation_validation": validation,
    }
