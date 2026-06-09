"""Privacy Causality Engine — evidence correlation and root-cause scoring (Phase 6)."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import yaml
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import resolve_rules_dir
from app.models import (
    Detection,
    EvidenceFile,
    Incident,
    NormalizedEvent,
    RootCauseScore,
    ScannerEvidenceRecord,
)
from app.models.enums import IncidentStatus
from app.models.root_cause_analysis import RootCauseAnalysis
from app.services import confidence_service, root_cause_exposure_facts_service
from app.services import root_cause_analysis_service, root_cause_ontology_service

RETEST_EVIDENCE_TYPES = {"fixed_log", "fixed_scan"}


@dataclass
class EvidenceContext:
    incident_id: str
    incident: Incident
    detections: list[Detection] = field(default_factory=list)
    events: list[NormalizedEvent] = field(default_factory=list)
    evidence_files: list[EvidenceFile] = field(default_factory=list)
    sensitive_types: set[str] = field(default_factory=set)
    evidence_types_present: set[str] = field(default_factory=set)
    evidence_ids_by_type: dict[str, list[str]] = field(default_factory=dict)
    supporting_evidence_ids: set[str] = field(default_factory=set)
    event_types: set[str] = field(default_factory=set)
    raw_references: list[str] = field(default_factory=list)
    masked_messages: list[str] = field(default_factory=list)
    event_severities: set[str] = field(default_factory=set)
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    scanner_records: list[ScannerEvidenceRecord] = field(default_factory=list)
    scanner_services: set[str] = field(default_factory=set)
    scanner_endpoints: set[str] = field(default_factory=set)
    scanner_timestamps: list[datetime] = field(default_factory=list)
    evidence_type_by_id: dict[str, str] = field(default_factory=dict)
    remediation_action_ids: list[str] = field(default_factory=list)
    # Phase L: structured exposure facts (safe dicts — see
    # `root_cause_exposure_facts_service.ExposureFact.as_dict`) used both as
    # an optional signal source (`exposure_fact_type_at_location`) and to
    # evaluate ontology-category boosts. Defaults to empty so existing
    # callers that construct `EvidenceContext` directly (tests, older call
    # sites) are unaffected.
    exposure_facts: list[dict] = field(default_factory=list)


@dataclass
class ScoredCause:
    likely_root_cause: str
    display_name: str
    base_score: float
    final_score: float
    confidence_band: str
    supporting_evidence_ids: list[str]
    missing_evidence: list[str]
    recommended_fix: str
    human_review_required: bool = True
    supporting_only: bool = False
    score_breakdown: list[dict] = field(default_factory=list)
    matched_signals: list[dict] = field(default_factory=list)
    negative_signals: list[dict] = field(default_factory=list)
    correlation_reasons: list[str] = field(default_factory=list)
    contradicting_evidence: list[dict] = field(default_factory=list)
    evidence_roles: list[dict] = field(default_factory=list)
    suggested_actions: list[dict] = field(default_factory=list)
    context_evidence_ids: list[str] = field(default_factory=list)
    remediation_evidence_ids: list[str] = field(default_factory=list)
    retest_evidence_ids: list[str] = field(default_factory=list)


@dataclass
class AnalyseIncidentResult:
    incident_id: str
    status: str
    skipped: bool = False
    root_cause_count: int = 0
    top_likely_cause: str | None = None
    top_confidence_band: str | None = None
    error: str | None = None


@dataclass
class AnalyseAllResult:
    results: list[AnalyseIncidentResult] = field(default_factory=list)
    total_scored: int = 0


@dataclass
class SignalEvaluation:
    signal_name: str
    matched: bool
    weight: float
    match_type: str
    evidence_ids: list[str] = field(default_factory=list)
    reason: str = ""
    is_negative: bool = False
    is_contradiction: bool = False
    confidence_effect: float = 0.0
    time_context: str | None = None


def load_root_cause_rules() -> dict:
    path = resolve_rules_dir() / "root_cause_rules.yaml"
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def generate_root_cause_id() -> str:
    return f"RCA-{uuid.uuid4().hex[:12]}"


def build_evidence_context(
    db: Session,
    incident_id: str,
    *,
    excluded_evidence_ids: set[str] | None = None,
) -> EvidenceContext:
    excluded_evidence_ids = excluded_evidence_ids or set()
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise KeyError(f"Incident not found: {incident_id}")

    detections = list(
        db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    )
    detections = [
        item for item in detections if item.evidence_id not in excluded_evidence_ids
    ]
    events = list(
        db.scalars(
            select(NormalizedEvent)
            .where(NormalizedEvent.linked_incident_id == incident_id)
            .order_by(NormalizedEvent.timestamp, NormalizedEvent.id)
        ).all()
    )
    events = [
        item for item in events if item.evidence_id not in excluded_evidence_ids
    ]
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

    scanner_records = list(
        db.scalars(
            select(ScannerEvidenceRecord)
            .where(ScannerEvidenceRecord.linked_incident_id == incident_id)
            .order_by(ScannerEvidenceRecord.imported_at, ScannerEvidenceRecord.id)
        ).all()
    )
    scanner_records = [
        item
        for item in scanner_records
        if item.linked_evidence_id not in excluded_evidence_ids
    ]

    from app.models.remediation_action import RemediationAction

    remediation_action_ids = list(
        db.scalars(
            select(RemediationAction.remediation_action_id)
            .where(RemediationAction.incident_id == incident_id)
            .order_by(RemediationAction.remediation_action_id)
        ).all()
    )

    ctx = EvidenceContext(
        incident_id=incident_id,
        incident=incident,
        detections=detections,
        events=events,
        evidence_files=evidence_files,
        scanner_records=scanner_records,
        remediation_action_ids=remediation_action_ids,
    )

    for det in detections:
        ctx.sensitive_types.add(det.sensitive_type)
        if det.evidence_id:
            ctx.supporting_evidence_ids.add(det.evidence_id)

    for ev in events:
        ctx.supporting_evidence_ids.add(ev.evidence_id)
        if ev.event_type:
            ctx.event_types.add(ev.event_type)
        if ev.raw_reference:
            ctx.raw_references.append(ev.raw_reference)
        if ev.masked_message:
            ctx.masked_messages.append(ev.masked_message)
        if ev.severity:
            ctx.event_severities.add(ev.severity.value)
        if ctx.first_event_at is None or ev.timestamp < ctx.first_event_at:
            ctx.first_event_at = ev.timestamp
        if ctx.last_event_at is None or ev.timestamp > ctx.last_event_at:
            ctx.last_event_at = ev.timestamp

    for ef in evidence_files:
        et = ef.evidence_type.value
        ctx.evidence_types_present.add(et)
        ctx.evidence_ids_by_type.setdefault(et, []).append(ef.evidence_id)
        ctx.supporting_evidence_ids.add(ef.evidence_id)
        ctx.evidence_type_by_id[ef.evidence_id] = et

    for scanner in scanner_records:
        if scanner.service_hint:
            ctx.scanner_services.add(scanner.service_hint.lower())
        if scanner.endpoint_hint:
            ctx.scanner_endpoints.add(scanner.endpoint_hint.lower())
        if scanner.detected_at:
            ctx.scanner_timestamps.append(scanner.detected_at)
        if scanner.linked_evidence_id:
            ctx.supporting_evidence_ids.add(scanner.linked_evidence_id)

    exposure_facts = root_cause_exposure_facts_service.build_exposure_facts(db, incident_id)
    ctx.exposure_facts = [
        fact.as_dict()
        for fact in exposure_facts
        if fact.evidence_id not in excluded_evidence_ids
    ]

    return ctx


def _minutes_between(a: datetime | None, b: datetime | None) -> int | None:
    if not a or not b:
        return None
    return int(abs((a - b).total_seconds()) / 60)


def _signal_name(signal: dict) -> str:
    return str(signal.get("name") or signal.get("match") or "signal")


def _evaluate_signal(ctx: EvidenceContext, signal: dict, conf_rules: dict) -> SignalEvaluation:
    match_type = str(signal.get("match", ""))
    value = signal.get("value")
    weight = float(signal.get("weight", 0))
    reason = str(signal.get("reason") or "Evidence suggests this signal is relevant.")
    evidence_ids: list[str] = []
    matched = False
    time_context: str | None = None

    if match_type == "event_type_contains":
        needle = str(value).lower()
        matched = any(needle in (et or "").lower() for et in ctx.event_types)
        if matched:
            evidence_ids = [ev.evidence_id for ev in ctx.events if needle in (ev.event_type or "").lower()]
    elif match_type == "raw_reference_contains":
        needle = str(value).lower()
        matched = any(needle in ref.lower() for ref in ctx.raw_references)
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if needle in (ev.raw_reference or "").lower()
            ]
    elif match_type == "raw_reference_matches_any":
        needles = [str(v).lower() for v in (value or [])]
        matched = any(any(n in ref.lower() for n in needles) for ref in ctx.raw_references) if needles else False
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if any(n in (ev.raw_reference or "").lower() for n in needles)
            ]
    elif match_type == "masked_message_contains":
        needle = str(value).lower()
        matched = any(needle in msg.lower() for msg in ctx.masked_messages)
        if matched:
            evidence_ids = [ev.evidence_id for ev in ctx.events if needle in (ev.masked_message or "").lower()]
    elif match_type == "masked_message_matches_any":
        needles = [str(v).lower() for v in (value or [])]
        matched = any(any(n in msg.lower() for n in needles) for msg in ctx.masked_messages) if needles else False
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if any(n in (ev.masked_message or "").lower() for n in needles)
            ]
    elif match_type == "sensitive_types_any":
        expected = set(value or [])
        matched = bool(ctx.sensitive_types & expected)
        if matched:
            evidence_ids = [
                det.evidence_id
                for det in ctx.detections
                if det.evidence_id and det.sensitive_type in expected
            ]
    elif match_type == "sensitive_type_present":
        matched = str(value) in ctx.sensitive_types
        if matched:
            evidence_ids = [
                det.evidence_id
                for det in ctx.detections
                if det.evidence_id and det.sensitive_type == str(value)
            ]
    elif match_type == "event_severity":
        matched = str(value) in ctx.event_severities
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if ev.severity and ev.severity.value == str(value)
            ]
    elif match_type == "endpoint_match_incident":
        endpoint = (ctx.incident.affected_endpoint or "").lower()
        matched = bool(endpoint) and any(endpoint in (ev.endpoint or "").lower() for ev in ctx.events)
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if endpoint in (ev.endpoint or "").lower()
            ]
    elif match_type == "service_match_incident":
        service = (ctx.incident.affected_service or "").lower()
        matched = bool(service) and any((ev.service_name or "").lower() == service for ev in ctx.events)
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if (ev.service_name or "").lower() == service
            ]
    elif match_type == "endpoint_and_service_match":
        endpoint = (ctx.incident.affected_endpoint or "").lower()
        service = (ctx.incident.affected_service or "").lower()
        matched = bool(endpoint and service) and any(
            endpoint in (ev.endpoint or "").lower() and (ev.service_name or "").lower() == service
            for ev in ctx.events
        )
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if endpoint in (ev.endpoint or "").lower()
                and (ev.service_name or "").lower() == service
            ]
    elif match_type == "evidence_type_present":
        et = str(value)
        matched = et in ctx.evidence_types_present
        if matched:
            evidence_ids = list(ctx.evidence_ids_by_type.get(et, []))
    elif match_type == "evidence_type_absent":
        matched = str(value) not in ctx.evidence_types_present
    elif match_type == "event_type_absent":
        needle = str(value).lower()
        matched = not any(needle in (et or "").lower() for et in ctx.event_types)
    elif match_type == "detection_count_at_least":
        matched = len(ctx.detections) >= int(value or 0)
        if matched:
            evidence_ids = [d.evidence_id for d in ctx.detections if d.evidence_id]
    elif match_type == "service_or_endpoint_mismatch":
        incident_service = (ctx.incident.affected_service or "").lower()
        incident_endpoint = (ctx.incident.affected_endpoint or "").lower()
        matched = any(
            (
                incident_service
                and ev.service_name
                and ev.service_name.lower() != incident_service
            )
            or (
                incident_endpoint
                and ev.endpoint
                and incident_endpoint not in ev.endpoint.lower()
            )
            for ev in ctx.events
        )
        if matched:
            evidence_ids = [
                ev.evidence_id
                for ev in ctx.events
                if (
                    incident_service
                    and ev.service_name
                    and ev.service_name.lower() != incident_service
                )
                or (
                    incident_endpoint
                    and ev.endpoint
                    and incident_endpoint not in ev.endpoint.lower()
                )
            ]
    elif match_type == "old_evidence_outside_time_window":
        stale_days = int((conf_rules.get("time_windows") or {}).get("stale_evidence_days", 30))
        if ctx.first_event_at and ctx.last_event_at:
            window_start = ctx.first_event_at - timedelta(days=stale_days)
            matched = any(ev.timestamp < window_start for ev in ctx.events)
    elif match_type == "deployment_before_incident_within_minutes":
        minutes = int((value or (conf_rules.get("time_windows") or {}).get("deployment_strong_minutes", 60)))
        if ctx.first_event_at:
            deploy_events = [
                ev for ev in ctx.events
                if ctx.evidence_type_by_id.get(ev.evidence_id) == "deployment_log"
                and ev.timestamp <= ctx.first_event_at
            ]
            if deploy_events:
                nearest = sorted(deploy_events, key=lambda ev: ctx.first_event_at - ev.timestamp)[0]
                diff_min = _minutes_between(ctx.first_event_at, nearest.timestamp) or 0
                matched = diff_min <= minutes
                evidence_ids = [nearest.evidence_id]
                time_context = f"Deployment event occurred {diff_min} minutes before first exposure."
    elif match_type == "access_event_near_incident_minutes":
        minutes = int((value or (conf_rules.get("time_windows") or {}).get("access_event_strong_minutes", 15)))
        if ctx.first_event_at:
            access_events = [
                ev for ev in ctx.events
                if ctx.evidence_type_by_id.get(ev.evidence_id) == "access_event"
            ]
            nearby: list[NormalizedEvent] = []
            for ev in access_events:
                diff = _minutes_between(ctx.first_event_at, ev.timestamp)
                if diff is not None and diff <= minutes:
                    nearby.append(ev)
            matched = bool(nearby)
            evidence_ids = [ev.evidence_id for ev in nearby]
            if nearby:
                diff0 = _minutes_between(ctx.first_event_at, nearby[0].timestamp) or 0
                time_context = f"Access-control event occurred {diff0} minutes from first exposure."
    elif match_type == "scanner_same_service":
        service = (ctx.incident.affected_service or "").lower()
        matched = bool(service) and service in ctx.scanner_services
        if matched:
            evidence_ids = [
                item.linked_evidence_id
                for item in ctx.scanner_records
                if item.linked_evidence_id
                and (item.service_hint or "").lower() == service
            ]
    elif match_type == "scanner_same_endpoint":
        endpoint = (ctx.incident.affected_endpoint or "").lower()
        matched = bool(endpoint) and any(endpoint in ep for ep in ctx.scanner_endpoints)
        if matched:
            evidence_ids = [
                item.linked_evidence_id
                for item in ctx.scanner_records
                if item.linked_evidence_id
                and endpoint in (item.endpoint_hint or "").lower()
            ]
    elif match_type == "exposure_fact_type_at_location":
        # Phase L: structured exposure facts as a first-class signal source.
        # `value` is {"sensitive_types": [...], "exposure_locations": [...]}.
        spec = value if isinstance(value, dict) else {}
        wanted_types = {str(t) for t in (spec.get("sensitive_types") or [])}
        wanted_locations = {str(loc) for loc in (spec.get("exposure_locations") or [])}
        matching_facts = [
            fact
            for fact in ctx.exposure_facts
            if (not wanted_types or fact.get("sensitive_type") in wanted_types)
            and (not wanted_locations or fact.get("exposure_location") in wanted_locations)
            and fact.get("sensitive_type")
            and fact.get("exposure_location")
        ]
        matched = bool(matching_facts)
        if matched:
            evidence_ids = [fact.get("evidence_id") for fact in matching_facts if fact.get("evidence_id")]

    if matched and not evidence_ids:
        for et in signal.get("evidence_types") or []:
            evidence_ids.extend(ctx.evidence_ids_by_type.get(et, []))
    evidence_ids = list(dict.fromkeys([x for x in evidence_ids if x]))
    return SignalEvaluation(
        signal_name=_signal_name(signal),
        matched=matched,
        weight=weight,
        match_type=match_type,
        evidence_ids=evidence_ids,
        reason=reason,
        confidence_effect=weight if matched else 0.0,
        time_context=time_context,
    )


def _signal_matches(ctx: EvidenceContext, signal: dict) -> bool:
    return _evaluate_signal(ctx, signal, confidence_service.load_confidence_rules()).matched


_TYPE_MISSING_KEY = {
    "api_log": "missing_api_log",
    "runtime_log": "missing_runtime_log",
    "semgrep_report": "missing_code_scan",
    "deployment_log": "missing_deployment_record",
    "access_event": "missing_access_event",
    "gitleaks_report": "missing_secret_scan",
    "trivy_report": "missing_dependency_scan",
    "fixed_log": "missing_retest_evidence",
    "fixed_scan": "missing_retest_evidence",
}


def _collect_missing_evidence(ctx: EvidenceContext, cause_rule: dict) -> list[str]:
    missing_keys: list[str] = []
    for req_type in cause_rule.get("required_evidence_types") or []:
        if req_type not in ctx.evidence_types_present:
            key = _TYPE_MISSING_KEY.get(req_type, f"missing_{req_type}")
            missing_keys.append(key)
    return missing_keys


def _timestamp_inconsistent(ctx: EvidenceContext, rules: dict) -> bool:
    if not ctx.first_event_at or not ctx.last_event_at:
        return False
    gap_hours = rules.get("timestamp_gap_hours", 48)
    delta = ctx.last_event_at - ctx.first_event_at
    return delta > timedelta(hours=gap_hours)


def _is_retest_only_signal(ctx: EvidenceContext, evidence_ids: list[str]) -> bool:
    """True when every evidence id backing a matched signal is retest-only evidence.

    Retest evidence (fixed_log/fixed_scan) proves a fix was verified, not that the
    candidate cause was the original root cause. Signals matched solely on such
    evidence must not contribute weight or count as original-cause support.
    """
    if not evidence_ids:
        return False
    return all(
        ctx.evidence_type_by_id.get(eid) in RETEST_EVIDENCE_TYPES for eid in evidence_ids
    )


def _apply_ontology_boost(
    ctx: EvidenceContext, cause_rule: dict
) -> tuple[float, list[dict], list[str]]:
    """Bounded, transparent ontology boost for a candidate cause (Phase L/ontology).

    Fires only when structured exposure facts independently corroborate an
    ontology category mapped to this `likely_root_cause`. Every application
    is recorded as its own `score_breakdown` entry (`ontology_boost:<id>`)
    with the category's reason text, so the effect is fully auditable and
    never presented as a standalone verdict. Wording stays at
    "supports"/"correlates with" — never "proved caused by".
    """
    likely = cause_rule.get("likely_root_cause")
    if not likely or not ctx.exposure_facts:
        return 0.0, [], []
    ontology = root_cause_ontology_service.load_ontology()
    categories = ontology.categories_for_root_cause(str(likely))
    if not categories:
        return 0.0, [], []

    total = 0.0
    entries: list[dict] = []
    reasons: list[str] = []
    for category in categories:
        matched_evidence_ids: list[str] = []
        applications = 0
        for fact in ctx.exposure_facts:
            if applications >= max(1, category.max_applications):
                break
            if root_cause_ontology_service.category_matches_fact(
                category,
                sensitive_type=fact.get("sensitive_type"),
                exposure_location=fact.get("exposure_location"),
            ):
                applications += 1
                if fact.get("evidence_id"):
                    matched_evidence_ids.append(str(fact["evidence_id"]))
        if not applications:
            continue
        reason = category.reason or (
            f"Structured exposure facts correlate with the {category.display_name} ontology category."
        )
        total += category.boost_weight
        entries.append(
            {
                "signal_name": f"ontology_boost:{category.category_id}",
                "match_type": "ontology_category_match",
                "matched": True,
                "weight": category.boost_weight,
                "evidence_ids": list(dict.fromkeys(matched_evidence_ids)),
                "reason": reason,
                "is_negative": False,
                "is_contradiction": False,
                "time_context": None,
                "ontology_category_id": category.category_id,
                "ontology_version": ontology.version,
            }
        )
        reasons.append(reason)
    return total, entries, reasons


def score_candidate_cause(ctx: EvidenceContext, cause_rule: dict) -> ScoredCause:
    conf_rules = confidence_service.load_confidence_rules()
    likely = cause_rule["likely_root_cause"]
    display = cause_rule.get("display_name", likely.replace("_", " "))
    base = 0.0
    matched_supporting: set[str] = set()
    retest_only_evidence_ids: set[str] = set()
    score_breakdown: list[dict] = []
    matched_signals: list[dict] = []
    negative_signals: list[dict] = []
    contradicting_evidence: list[dict] = []
    correlation_reasons: list[str] = []

    for signal in cause_rule.get("signals") or []:
        ev = _evaluate_signal(ctx, signal, conf_rules)
        if ev.matched and _is_retest_only_signal(ctx, ev.evidence_ids):
            retest_only_evidence_ids.update(ev.evidence_ids)
            ev = SignalEvaluation(
                signal_name=ev.signal_name,
                matched=False,
                weight=0.0,
                match_type=ev.match_type,
                evidence_ids=ev.evidence_ids,
                reason=ev.reason,
                is_negative=ev.is_negative,
                is_contradiction=ev.is_contradiction,
                confidence_effect=ev.confidence_effect,
                time_context=ev.time_context,
            )
        if ev.matched:
            base += ev.weight
            matched_supporting.update(ev.evidence_ids)
            matched_signals.append(
                {
                    "signal_name": ev.signal_name,
                    "match_type": ev.match_type,
                    "weight": ev.weight,
                    "evidence_ids": ev.evidence_ids,
                    "reason": ev.reason,
                }
            )
            correlation_reasons.append(ev.reason)
            if ev.time_context:
                correlation_reasons.append(ev.time_context)
        score_breakdown.append(
            {
                "signal_name": ev.signal_name,
                "match_type": ev.match_type,
                "matched": ev.matched,
                "weight": ev.weight,
                "evidence_ids": ev.evidence_ids,
                "reason": ev.reason,
                "is_negative": False,
                "is_contradiction": False,
                "time_context": ev.time_context,
            }
        )

    for signal in cause_rule.get("negative_signals") or []:
        ev = _evaluate_signal(ctx, signal, conf_rules)
        if ev.matched and _is_retest_only_signal(ctx, ev.evidence_ids):
            retest_only_evidence_ids.update(ev.evidence_ids)
            ev = SignalEvaluation(
                signal_name=ev.signal_name,
                matched=False,
                weight=0.0,
                match_type=ev.match_type,
                evidence_ids=ev.evidence_ids,
                reason=ev.reason,
                is_negative=ev.is_negative,
                is_contradiction=ev.is_contradiction,
                confidence_effect=ev.confidence_effect,
                time_context=ev.time_context,
            )
        if ev.matched:
            base += ev.weight
            matched_supporting.update(ev.evidence_ids)
            negative_signals.append(
                {
                    "signal_name": ev.signal_name,
                    "weight": ev.weight,
                    "evidence_ids": ev.evidence_ids,
                    "reason": ev.reason,
                }
            )
            correlation_reasons.append(ev.reason)
        score_breakdown.append(
            {
                "signal_name": ev.signal_name,
                "match_type": ev.match_type,
                "matched": ev.matched,
                "weight": ev.weight,
                "evidence_ids": ev.evidence_ids,
                "reason": ev.reason,
                "is_negative": True,
                "is_contradiction": False,
                "time_context": ev.time_context,
            }
        )

    for signal in cause_rule.get("contradiction_signals") or []:
        ev = _evaluate_signal(ctx, signal, conf_rules)
        if ev.matched and _is_retest_only_signal(ctx, ev.evidence_ids):
            retest_only_evidence_ids.update(ev.evidence_ids)
            ev = SignalEvaluation(
                signal_name=ev.signal_name,
                matched=False,
                weight=0.0,
                match_type=ev.match_type,
                evidence_ids=ev.evidence_ids,
                reason=ev.reason,
                is_negative=ev.is_negative,
                is_contradiction=ev.is_contradiction,
                confidence_effect=ev.confidence_effect,
                time_context=ev.time_context,
            )
        if ev.matched:
            base += ev.weight
            matched_supporting.update(ev.evidence_ids)
            for eid in ev.evidence_ids or []:
                contradicting_evidence.append({"evidence_id": eid, "reason": ev.reason})
            if not ev.evidence_ids:
                contradicting_evidence.append({"evidence_id": "unknown", "reason": ev.reason})
            correlation_reasons.append(ev.reason)
        score_breakdown.append(
            {
                "signal_name": ev.signal_name,
                "match_type": ev.match_type,
                "matched": ev.matched,
                "weight": ev.weight,
                "evidence_ids": ev.evidence_ids,
                "reason": ev.reason,
                "is_negative": True,
                "is_contradiction": True,
                "time_context": ev.time_context,
            }
        )

    ontology_boost, ontology_entries, ontology_reasons = _apply_ontology_boost(ctx, cause_rule)
    if ontology_entries:
        base += ontology_boost
        score_breakdown.extend(ontology_entries)
        correlation_reasons.extend(ontology_reasons)
        for entry in ontology_entries:
            matched_supporting.update(entry.get("evidence_ids") or [])
            matched_signals.append(
                {
                    "signal_name": entry["signal_name"],
                    "match_type": entry["match_type"],
                    "weight": entry["weight"],
                    "evidence_ids": entry["evidence_ids"],
                    "reason": entry["reason"],
                }
            )

    max_score = cause_rule.get("max_score", 1.0)
    max_cap = cause_rule.get("max_score_cap", max_score)
    base = min(base, float(max_cap))

    missing_keys = _collect_missing_evidence(ctx, cause_rule)
    final, penalty_labels = confidence_service.apply_penalties(base, missing_keys, conf_rules)

    missing_labels = list(penalty_labels)
    templates = cause_rule.get("missing_evidence_templates") or {}
    for key in missing_keys:
        label = templates.get(key)
        if label and label not in missing_labels:
            missing_labels.append(label)

    if _timestamp_inconsistent(ctx, conf_rules):
        final, extra = confidence_service.apply_penalties(
            final, ["timestamp_inconsistent"], conf_rules
        )
        missing_labels.extend(extra)

    contradicting_ids = {
        str(item.get("evidence_id"))
        for item in contradicting_evidence
        if item.get("evidence_id") and item.get("evidence_id") != "unknown"
    }
    evidence_by_id = {item.evidence_id: item for item in ctx.evidence_files}
    verification_ids = {
        evidence_id
        for evidence_id in matched_supporting
        if evidence_id in evidence_by_id
        and evidence_by_id[evidence_id].evidence_type.value in {"fixed_log", "fixed_scan"}
    }
    verification_ids = verification_ids | retest_only_evidence_ids
    supporting_ids = sorted(matched_supporting - contradicting_ids - verification_ids)
    if len(supporting_ids) <= 1 and base > 0:
        cap = float(conf_rules.get("single_source_cap", 0.74))
        if final > cap:
            final = cap
        single_label = (conf_rules.get("penalties") or {}).get("single_weak_source", {}).get(
            "label"
        )
        if single_label and single_label not in missing_labels:
            missing_labels.append(single_label)

    if cause_rule.get("supporting_only") and final > float(cause_rule.get("max_score_cap", 0.44)):
        final = float(cause_rule.get("max_score_cap", 0.44))
    final = max(0.0, min(1.0, final))

    if contradicting_evidence:
        correlation_reasons.append(
            "Confidence was reduced because contradicting or weak evidence was found."
        )

    evidence_roles: list[dict] = []
    seen_roles: set[tuple[str, str]] = set()
    for evidence_id in supporting_ids:
        evf = evidence_by_id.get(evidence_id)
        role = "supporting_context"
        reason = "A matched signal links this evidence to the candidate cause."
        evidence_type = evf.evidence_type.value if evf else ""
        if evidence_type in {"api_log", "runtime_log"}:
            role = "primary_symptom"
            reason = "Masked detections were linked to log evidence."
        elif evidence_type in {"semgrep_report", "gitleaks_report"}:
            role = "direct_technical_cause_evidence"
            reason = "A matched code or secret scanning signal supports this candidate cause."
        elif evidence_type in {"deployment_log"}:
            role = "temporal_context"
            reason = "Deployment timing provides correlation context."
        elif evidence_type in {"access_event"}:
            role = "access_control_context"
            reason = "Access-control event may indicate possible contribution."
        elif evidence_type in {"trivy_report"}:
            role = "dependency_context"
            reason = "Dependency findings provide supporting context."
        key = (evidence_id, role)
        if key not in seen_roles:
            evidence_roles.append({"evidence_id": evidence_id, "role": role, "reason": reason})
            seen_roles.add(key)
    for evidence_id in sorted(verification_ids):
        evidence_roles.append(
            {
                "evidence_id": evidence_id,
                "role": "verification_evidence",
                "reason": "Retest evidence is kept separate from original-cause support.",
            }
        )
    for item in contradicting_evidence:
        eid = item.get("evidence_id") or "unknown"
        key = (eid, "contradiction")
        if key not in seen_roles:
            evidence_roles.append(
                {"evidence_id": eid, "role": "contradiction", "reason": item.get("reason")}
            )
            seen_roles.add(key)

    suggested_actions: list[dict] = []
    suggestion_map = {
        "Missing code scan finding": "Upload code scan evidence for the affected service.",
        "Missing deployment record": "Upload deployment evidence for the release active during the incident.",
        "Missing access-control event": "Upload access-control logs around the incident time window.",
        "Missing retest evidence": "Upload fixed/retest evidence after remediation.",
        "Missing human review": "Ask a security analyst to review the likely cause and supporting evidence.",
    }
    for item in confidence_service.format_missing_evidence(missing_labels):
        suggested_actions.append(
            {
                "missing_evidence": item,
                "suggested_action": suggestion_map.get(
                    item, "Collect additional corroborating evidence for this missing item."
                ),
            }
        )

    context_role_names = {
        "supporting_context",
        "temporal_context",
        "access_control_context",
        "dependency_context",
    }
    context_evidence_ids = sorted(
        {
            str(role.get("evidence_id"))
            for role in evidence_roles
            if role.get("role") in context_role_names and role.get("evidence_id")
        }
    )
    retest_evidence_ids = sorted(verification_ids)
    remediation_evidence_ids = list(ctx.remediation_action_ids)

    band = confidence_service.score_to_band(final, conf_rules)
    return ScoredCause(
        likely_root_cause=likely,
        display_name=display,
        base_score=round(base, 4),
        final_score=round(final, 4),
        confidence_band=band,
        supporting_evidence_ids=supporting_ids,
        missing_evidence=confidence_service.format_missing_evidence(missing_labels),
        recommended_fix=(cause_rule.get("recommended_fix") or "").strip(),
        supporting_only=bool(cause_rule.get("supporting_only")),
        score_breakdown=score_breakdown,
        matched_signals=matched_signals,
        negative_signals=negative_signals,
        correlation_reasons=list(dict.fromkeys(correlation_reasons)),
        contradicting_evidence=contradicting_evidence,
        evidence_roles=evidence_roles,
        suggested_actions=suggested_actions,
        context_evidence_ids=context_evidence_ids,
        remediation_evidence_ids=remediation_evidence_ids,
        retest_evidence_ids=retest_evidence_ids,
    )


def _rank_causes(ctx: EvidenceContext, rules: dict) -> list[ScoredCause]:
    scored: list[ScoredCause] = []
    for cause_rule in rules.get("causes") or []:
        if cause_rule.get("supporting_only") and not _has_any_signal(ctx, cause_rule):
            continue
        item = score_candidate_cause(ctx, cause_rule)
        if item.final_score > 0:
            scored.append(item)
    scored.sort(key=lambda s: (-s.final_score, s.likely_root_cause))
    top_n = int(rules.get("top_n", 5))
    if scored and scored[0].supporting_only:
        non_support = [s for s in scored if not s.supporting_only]
        if non_support:
            scored = non_support + [s for s in scored if s.supporting_only]
    return scored[:top_n]


def rank_causes(ctx: EvidenceContext, rules: dict | None = None) -> list[ScoredCause]:
    return _rank_causes(ctx, rules or load_root_cause_rules())


def _has_any_signal(ctx: EvidenceContext, cause_rule: dict) -> bool:
    all_signals = (
        (cause_rule.get("signals") or [])
        + (cause_rule.get("negative_signals") or [])
        + (cause_rule.get("contradiction_signals") or [])
    )
    return any(_signal_matches(ctx, sig) for sig in all_signals)


def generate_analysis_id() -> str:
    return f"RCA-ANALYSIS-{uuid.uuid4().hex[:12]}"


def compute_rules_version(rules: dict) -> str:
    """Deterministic fingerprint of the root-cause rules + ontology in effect.

    Used to detect (for display, not automatic invalidation) that an old
    analysis was produced under different scoring rules.
    """
    ontology = root_cause_ontology_service.load_ontology()
    blob = json.dumps(rules, sort_keys=True, default=str).encode("utf-8")
    rules_hash = hashlib.sha256(blob).hexdigest()[:16]
    return f"rules:{rules_hash}:ontology:{ontology.version}"


def compute_evidence_snapshot_hash(ctx: EvidenceContext) -> str:
    """Deterministic fingerprint of the evidence an analysis was based on.

    Two analyses of the same incident with an identical snapshot hash were
    computed from the same underlying evidence set; a changed hash after new
    evidence is linked is the trigger `mark_stale` callers use to flag a
    current analysis as outdated (Phase N).
    """
    payload = {
        "detections": sorted(d.detection_id for d in ctx.detections),
        "events": sorted(e.event_id for e in ctx.events),
        "evidence_files": sorted(e.evidence_id for e in ctx.evidence_files),
        "scanner_records": sorted(
            s.scanner_evidence_id for s in ctx.scanner_records if s.scanner_evidence_id
        ),
        "remediation_action_ids": sorted(ctx.remediation_action_ids),
        "exposure_facts": sorted(str(fact.get("fact_id", "")) for fact in ctx.exposure_facts),
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]


def next_analysis_version(existing_rows: list[RootCauseScore]) -> int:
    """Next sequential `analysis_version` for an incident (pure — no I/O)."""
    if not existing_rows:
        return 1
    return max((row.analysis_version or 1) for row in existing_rows) + 1


def apply_staleness_to_rows(rows: list[RootCauseScore], reason: str) -> int:
    """Mark rows stale with `reason` in place (pure — no I/O). Returns count changed."""
    changed = 0
    for row in rows:
        if row.stale and row.stale_reason == reason:
            continue
        row.stale = True
        row.stale_reason = reason
        changed += 1
    return changed


def supersede_rows(
    rows: list[RootCauseScore],
    new_analysis_id: str,
    *,
    reason: str = "Superseded by a newer root-cause analysis.",
) -> int:
    """Mark the most recent existing analysis batch as superseded (pure — no I/O).

    Only rows belonging to the latest `analysis_version` in `rows` are
    touched; earlier historical batches keep whatever `superseded_by_
    analysis_id` chain they already had from their own supersession.
    """
    if not rows:
        return 0
    latest_version = max((row.analysis_version or 1) for row in rows)
    changed = 0
    for row in rows:
        if (row.analysis_version or 1) != latest_version:
            continue
        if row.superseded_by_analysis_id == new_analysis_id:
            continue
        row.superseded_by_analysis_id = new_analysis_id
        row.stale = True
        row.stale_reason = reason
        changed += 1
    return changed


def mark_stale(db: Session, incident_id: str, reason: str) -> int:
    """Flag the incident's current root-cause analysis as stale (Phase N).

    Callers (detection creation, alert linking, CI/CD evidence linking,
    scanner evidence linking) invoke this whenever new evidence is added or
    linked to an already-analysed incident. Does not commit — the caller's
    existing transaction owns that. Safe to call even if the incident has
    never been analysed (returns 0).
    """
    rows = list_root_cause_scores(db, incident_id)
    if not rows:
        return 0
    changed = apply_staleness_to_rows(rows, reason)
    if changed:
        db.add_all(rows)
    current = root_cause_analysis_service.get_current_analysis(db, incident_id)
    if isinstance(current, RootCauseAnalysis):
        root_cause_analysis_service.mark_analysis_stale(db, current.analysis_id, reason)
    return changed


def get_root_cause_status(db: Session, incident_id: str) -> dict:
    """Lightweight status summary of an incident's current root-cause analysis."""
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise KeyError(f"Incident not found: {incident_id}")
    rows = list_root_cause_scores(db, incident_id)
    if not rows:
        return {
            "incident_id": incident_id,
            "analysed": False,
            "analysis_id": None,
            "analysis_version": None,
            "rules_version": None,
            "evidence_snapshot_hash": None,
            "analysed_at": None,
            "stale": False,
            "stale_reason": None,
            "root_cause_count": 0,
            "top_likely_cause": None,
            "superseded_by_analysis_id": None,
        }
    sample = rows[0]
    top = next((row for row in rows if row.rank == 1), rows[0])
    return {
        "incident_id": incident_id,
        "analysed": True,
        "analysis_id": sample.analysis_id,
        "analysis_version": sample.analysis_version,
        "rules_version": sample.rules_version,
        "evidence_snapshot_hash": sample.evidence_snapshot_hash,
        "analysed_at": sample.analysed_at,
        "stale": any(row.stale for row in rows),
        "stale_reason": next((row.stale_reason for row in rows if row.stale_reason), None),
        "root_cause_count": len(rows),
        "top_likely_cause": top.likely_root_cause if top else None,
        "superseded_by_analysis_id": next(
            (row.superseded_by_analysis_id for row in rows if row.superseded_by_analysis_id),
            None,
        ),
    }


def _persist_scores(
    db: Session,
    incident_id: str,
    ranked: list[ScoredCause],
    *,
    analysis_id: str,
    analysis_version: int,
    rules_version: str,
    evidence_snapshot_hash: str,
    analysed_at: datetime,
) -> int:
    for rank, item in enumerate(ranked, start=1):
        db.add(
            RootCauseScore(
                root_cause_id=generate_root_cause_id(),
                incident_id=incident_id,
                cause_name=item.likely_root_cause,
                likely_root_cause=item.likely_root_cause,
                confidence=item.final_score,
                confidence_band=item.confidence_band,
                rank=rank,
                supporting_evidence_ids=item.supporting_evidence_ids,
                missing_evidence=item.missing_evidence,
                score_breakdown=item.score_breakdown,
                matched_signals=item.matched_signals,
                negative_signals=item.negative_signals,
                correlation_reasons=item.correlation_reasons,
                contradicting_evidence=item.contradicting_evidence,
                context_evidence_ids=item.context_evidence_ids,
                remediation_evidence_ids=item.remediation_evidence_ids,
                retest_evidence_ids=item.retest_evidence_ids,
                evidence_roles=item.evidence_roles,
                suggested_actions=item.suggested_actions,
                recommended_fix=item.recommended_fix,
                human_review_required=True,
                explanation=None,
                analysis_id=analysis_id,
                analysis_version=analysis_version,
                rules_version=rules_version,
                evidence_snapshot_hash=evidence_snapshot_hash,
                analysed_at=analysed_at,
                stale=False,
                stale_reason=None,
                superseded_by_analysis_id=None,
            )
        )
    return len(ranked)


def _update_incident_after_analyse(db: Session, incident: Incident, ctx: EvidenceContext) -> None:
    incident.status = IncidentStatus.UNDER_REVIEW
    if ctx.first_event_at:
        incident.first_seen = ctx.first_event_at
    if ctx.last_event_at:
        incident.last_seen = ctx.last_event_at
    db.add(incident)


def analyse_incident(
    db: Session,
    incident_id: str,
    *,
    force: bool = False,
) -> AnalyseIncidentResult:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:incident_id))"),
            {"incident_id": incident_id},
        )
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise KeyError(f"Incident not found: {incident_id}")

    existing_rows = list(
        db.scalars(
            select(RootCauseScore).where(RootCauseScore.incident_id == incident_id)
        ).all()
    )
    current_analysis = root_cause_analysis_service.get_current_analysis(db, incident_id)
    if current_analysis is not None and not current_analysis.stale and not force:
        current_rows = [
            row for row in existing_rows if row.analysis_id == current_analysis.analysis_id
        ]
        top = next((row for row in current_rows if row.rank == 1), None)
        return AnalyseIncidentResult(
            incident_id=incident_id,
            status="analysed",
            skipped=True,
            root_cause_count=len(current_rows),
            top_likely_cause=top.likely_root_cause if top else None,
            top_confidence_band=top.confidence_band if top else None,
        )

    detections = list(
        db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    )
    if not detections:
        return AnalyseIncidentResult(
            incident_id=incident_id,
            status="failed",
            error="No detections found for incident; run detect-all first",
        )

    try:
        ctx = build_evidence_context(db, incident_id)
        rules = load_root_cause_rules()
        ranked = _rank_causes(ctx, rules)
        if not ranked:
            return AnalyseIncidentResult(
                incident_id=incident_id,
                status="failed",
                error="No likely root causes scored above threshold",
            )

        # Phase N: never destroy history — supersede the previous batch (if
        # any) and persist the new one as its own version, so a later
        # remediation success can never rewrite an earlier causal analysis.
        analysis_id = generate_analysis_id()
        analysis_version = next_analysis_version(existing_rows)
        snapshot_hash = compute_evidence_snapshot_hash(ctx)
        rules_version = compute_rules_version(rules)
        analysed_at = datetime.now(timezone.utc)
        if existing_rows:
            supersede_rows(existing_rows, analysis_id)
            db.add_all(existing_rows)
        root_cause_analysis_service.create_analysis_record(
            db,
            analysis_id=analysis_id,
            incident_id=incident_id,
            analysis_version=analysis_version,
            evidence_snapshot_hash=snapshot_hash,
            rules_version=rules_version,
            analysed_at=analysed_at,
        )
        count = _persist_scores(
            db,
            incident_id,
            ranked,
            analysis_id=analysis_id,
            analysis_version=analysis_version,
            rules_version=rules_version,
            evidence_snapshot_hash=snapshot_hash,
            analysed_at=analysed_at,
        )
        _update_incident_after_analyse(db, incident, ctx)
        db.commit()
        top = ranked[0]
        return AnalyseIncidentResult(
            incident_id=incident_id,
            status="analysed",
            skipped=False,
            root_cause_count=count,
            top_likely_cause=top.likely_root_cause,
            top_confidence_band=top.confidence_band,
        )
    except Exception as exc:
        db.rollback()
        return AnalyseIncidentResult(
            incident_id=incident_id,
            status="failed",
            error=str(exc),
        )


def analyse_all_incidents(db: Session, *, force: bool = False) -> AnalyseAllResult:
    incident_ids = list(
        db.scalars(
            select(Detection.incident_id).distinct().order_by(Detection.incident_id)
        ).all()
    )
    batch = AnalyseAllResult()
    for iid in incident_ids:
        if not iid:
            continue
        result = analyse_incident(db, iid, force=force)
        batch.results.append(result)
        if not result.skipped and result.status == "analysed":
            batch.total_scored += result.root_cause_count
    return batch


def list_root_cause_scores(
    db: Session,
    incident_id: str,
    *,
    include_history: bool = False,
) -> list[RootCauseScore]:
    """Ranked root-cause rows for an incident.

    By default returns only the current (latest `analysis_version`) batch,
    preserving pre-Phase-N callers' expectation of "the" ranking for an
    incident. Pass `include_history=True` to see every superseded analysis
    version as well (Phase N).
    """
    stmt = select(RootCauseScore).where(RootCauseScore.incident_id == incident_id)
    if not include_history:
        latest_version_subquery = (
            select(func.max(RootCauseScore.analysis_version))
            .where(RootCauseScore.incident_id == incident_id)
            .scalar_subquery()
        )
        stmt = stmt.where(
            func.coalesce(RootCauseScore.analysis_version, 1)
            == func.coalesce(latest_version_subquery, 1)
        )
    stmt = stmt.order_by(RootCauseScore.rank, RootCauseScore.id)
    return list(db.scalars(stmt).all())


def list_incidents(db: Session) -> list[Incident]:
    return list(db.scalars(select(Incident).order_by(Incident.id)).all())


def get_incident(db: Session, incident_id: str) -> Incident | None:
    return db.scalar(select(Incident).where(Incident.incident_id == incident_id))


def get_incident_trace(db: Session, incident_id: str) -> dict:
    incident = get_incident(db, incident_id)
    if not incident:
        raise KeyError(f"Incident not found: {incident_id}")

    ctx = build_evidence_context(db, incident_id)
    scores = list_root_cause_scores(db, incident_id)

    timeline = []
    for ev in sorted(ctx.events, key=lambda e: (e.timestamp, e.id)):
        related = [
            {
                "detection_id": d.detection_id,
                "sensitive_type": d.sensitive_type,
                "masked_value": d.masked_value,
            }
            for d in ctx.detections
            if d.normalized_event_id == ev.event_id
        ]
        timeline.append(
            {
                "event_id": ev.event_id,
                "evidence_id": ev.evidence_id,
                "timestamp": ev.timestamp.isoformat(),
                "source_type": ev.source_type,
                "service_name": ev.service_name,
                "endpoint": ev.endpoint,
                "event_type": ev.event_type,
                "masked_message": ev.masked_message,
                "detections": related,
            }
        )

    ranked_causes = [
        {
            "root_cause_id": s.root_cause_id,
            "rank": s.rank,
            "likely_root_cause": s.likely_root_cause,
            "confidence": s.confidence,
            "confidence_band": s.confidence_band,
            "supporting_evidence_ids": s.supporting_evidence_ids or [],
            "missing_evidence": s.missing_evidence or [],
            "score_breakdown": s.score_breakdown or [],
            "matched_signals": s.matched_signals or [],
            "negative_signals": s.negative_signals or [],
            "correlation_reasons": s.correlation_reasons or [],
            "contradicting_evidence": s.contradicting_evidence or [],
            "evidence_roles": s.evidence_roles or [],
            "suggested_actions": s.suggested_actions or [],
            "recommended_fix": s.recommended_fix,
            "human_review_required": s.human_review_required,
            "wording": "likely cause",
            "analysis_id": s.analysis_id,
            "analysis_version": s.analysis_version,
            "stale": s.stale,
            "stale_reason": s.stale_reason,
        }
        for s in scores
    ]

    aggregate_missing: list[str] = []
    aggregate_reasons: list[str] = []
    aggregate_roles: list[dict] = []
    aggregate_breakdown: list[dict] = []
    aggregate_contradictions: list[dict] = []
    aggregate_actions: list[dict] = []
    for s in scores:
        for item in s.missing_evidence or []:
            if item not in aggregate_missing:
                aggregate_missing.append(item)
        for item in s.correlation_reasons or []:
            if item not in aggregate_reasons:
                aggregate_reasons.append(item)
        for item in s.evidence_roles or []:
            if item not in aggregate_roles:
                aggregate_roles.append(item)
        for item in s.score_breakdown or []:
            aggregate_breakdown.append(item)
        for item in s.contradicting_evidence or []:
            if item not in aggregate_contradictions:
                aggregate_contradictions.append(item)
        for item in s.suggested_actions or []:
            if item not in aggregate_actions:
                aggregate_actions.append(item)

    top_cause = scores[0] if scores else None
    why_ranked = [x.get("reason") for x in (top_cause.matched_signals or []) if x.get("reason")] if top_cause else []
    if not why_ranked:
        why_ranked = ["Available evidence suggests this likely cause has the strongest support."]

    return {
        "incident_id": incident_id,
        "title": incident.title,
        "status": incident.status.value,
        "affected_service": incident.affected_service,
        "affected_endpoint": incident.affected_endpoint,
        "detection_count": len(ctx.detections),
        "evidence_count": len(ctx.evidence_files),
        "analysis_stale": any(s.stale for s in scores),
        "analysis_stale_reason": next((s.stale_reason for s in scores if s.stale_reason), None),
        "analysis_version": scores[0].analysis_version if scores else None,
        "timeline": timeline,
        "likely_root_causes": ranked_causes,
        "evidence_roles": aggregate_roles,
        "score_breakdowns": aggregate_breakdown,
        "correlation_reasons": aggregate_reasons,
        "contradicting_evidence": aggregate_contradictions,
        "missing_evidence": aggregate_missing,
        "suggested_actions": aggregate_actions,
        "trace_summary": {
            "what_happened": "Masked sensitive values were detected in incident-linked evidence.",
            "where_it_happened": incident.affected_endpoint,
            "strongest_likely_cause": top_cause.likely_root_cause if top_cause else None,
            "why_ranked_highest": why_ranked[:4],
            "what_is_missing": aggregate_missing[:5],
            "safe_conclusion": (
                "Evidence suggests the top-ranked item is the strongest likely cause, "
                "but human review is required."
            ),
        },
        "reviewer_warning": (
            "Root-cause ranking is based on available evidence and must be reviewed by a human analyst."
        ),
        "human_review_required": True,
        "disclaimer": "Ranked outcomes are likely causes supported by evidence, not confirmed blame.",
    }
