"""Sensitive data detection and masking over normalized events.

`detect_event` now runs the unified `sensitive_exposure_engine` (see
`docs/CORE_ENGINE_BASELINE_AUDIT.md`) instead of a private regex pass, so the
same value is classified the same way whether it is observed through the
Evidence upload path (this module) or the Live Monitor path
(`live_monitor_service`). `load_sensitive_rules`/`SensitiveRule` are kept for
existing callers/tests that inspect the legacy declarative rule set
directly; they are no longer used to decide what becomes a `Detection`.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import resolve_rules_dir
from app.models import Detection, EvidenceFile, NormalizedEvent
from app.models.enums import EvidenceType, ParsingStatus, Severity
from app.services import causality_engine, masking_service
from app.services import sensitive_candidate_detection_service as candidate_detection_service
from app.services import sensitive_exposure_engine as exposure_engine
from app.services.masking_service import MatchSpan


@dataclass
class SensitiveRule:
    name: str
    sensitive_type: str
    pattern: re.Pattern[str]
    confidence: float
    severity: Severity | None
    detector_name: str


@dataclass
class DetectEvidenceResult:
    evidence_id: str
    status: str
    detection_count: int = 0
    skipped: bool = False
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class DetectAllResult:
    results: list[DetectEvidenceResult] = field(default_factory=list)
    total_detections: int = 0


def load_sensitive_rules() -> list[SensitiveRule]:
    path = resolve_rules_dir() / "sensitive_data_rules.yaml"
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules: list[SensitiveRule] = []
    for entry in data.get("rules") or []:
        severity_raw = entry.get("severity")
        severity = None
        if severity_raw:
            try:
                severity = Severity(severity_raw.lower())
            except ValueError:
                severity = None
        rules.append(
            SensitiveRule(
                name=entry["name"],
                sensitive_type=entry["sensitive_type"],
                pattern=re.compile(entry["pattern"]),
                confidence=float(entry.get("confidence", 0.9)),
                severity=severity,
                detector_name=entry.get("detector_name", "regex_v1"),
            )
        )
    return rules


def hash_raw_value(value: str) -> str:
    """DEPRECATED for sensitive identifiers.

    Prefer `finding["value_fingerprint"]` or
    `sensitive_fingerprint_service.fingerprint` (HMAC). Unkeyed SHA-256 of
    low-entropy identifiers is brute-forceable and must not be used as a
    silent fallback for detection fingerprints. Kept only for legacy /
    non-sensitive content-hash call sites and tests.
    """

    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def fingerprint_for_detection(raw_value: str, sensitive_type: str, preferred: str | None = None) -> str | None:
    """Resolve a detection fingerprint without SHA-256 downgrade.

    Order: preferred HMAC from the engine → `sensitive_fingerprint_service`
    → `None` when HMAC is unavailable (column is nullable).
    """

    if preferred:
        return preferred
    from app.services import sensitive_fingerprint_service as fingerprint_service

    try:
        return fingerprint_service.fingerprint(raw_value, sensitive_type)["fingerprint"]
    except fingerprint_service.FingerprintUnavailableError:
        return None


def generate_detection_id() -> str:
    return f"DET-{uuid.uuid4().hex[:12]}"


# Maps the Evidence upload channel (`EvidenceType`) onto the exposure engine's
# `source_type` vocabulary so the same engine that backs Live Monitor infers
# exposure location for evidence-derived events too.
_EVIDENCE_TYPE_SOURCE_MAP: dict[EvidenceType, str] = {
    EvidenceType.API_LOG: "application_log",
    EvidenceType.RUNTIME_LOG: "runtime_log",
    EvidenceType.SIEM_ALERT: "siem_import",
    EvidenceType.SCANNER_BRIDGE_IMPORT: "scanner_bridge",
    EvidenceType.FIXED_LOG: "application_log",
    EvidenceType.FIXED_SCAN: "scanner_bridge",
    EvidenceType.DEPLOYMENT_LOG: "application_log",
    EvidenceType.ACCESS_EVENT: "application_log",
}

_ACTIONABLE_EXPOSURE_DECISIONS = {"unsafe_exposure", "uncertain"}

_SENSITIVITY_TO_SEVERITY: dict[str, Severity] = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _source_type_for_event(event: NormalizedEvent) -> str:
    evidence_type = event.evidence_file.evidence_type if event.evidence_file else None
    return _EVIDENCE_TYPE_SOURCE_MAP.get(evidence_type, "application_log")


def severity_for_finding(finding: dict) -> Severity:
    """Map an engine finding's `sensitivity_level` onto the DB `Severity` enum.

    Shared by `detect_event` and `live_monitor_service.process_event` so both
    ingestion paths derive severity the same way instead of each guessing
    independently or falling back to a hardcoded value.
    """
    return _SENSITIVITY_TO_SEVERITY.get(str(finding.get("sensitivity_level") or "").upper(), Severity.MEDIUM)


def _find_matches(text: str, rules: list[SensitiveRule]) -> list[MatchSpan]:
    spans: list[MatchSpan] = []
    for rule in rules:
        for match in rule.pattern.finditer(text):
            spans.append(
                MatchSpan(
                    start=match.start(),
                    end=match.end(),
                    sensitive_type=rule.sensitive_type,
                    raw_value=match.group(0),
                )
            )
    return _dedupe_spans(spans)


def _dedupe_spans(spans: list[MatchSpan]) -> list[MatchSpan]:
    if not spans:
        return []
    unique: dict[tuple[int, int, str], MatchSpan] = {}
    for span in spans:
        key = (span.start, span.end, span.raw_value)
        unique[key] = span
    ordered = sorted(unique.values(), key=lambda s: (-(s.end - s.start), s.start))
    kept: list[MatchSpan] = []
    for span in ordered:
        if any(
            span.start >= other.start and span.end <= other.end and span != other
            for other in kept
        ):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: s.start)


def detect_event(
    db: Session,
    event: NormalizedEvent,
    *,
    incident_id: str,
    rules: list[SensitiveRule] | None = None,
) -> list[Detection]:
    """Detect sensitive-data exposure in `event` via the unified exposure engine.

    `rules` is accepted (and ignored) for backward compatibility with callers
    written against the legacy regex-rules signature; detection decisions now
    come exclusively from `sensitive_exposure_engine.analyse`, the same
    pipeline `live_monitor_service.process_event` uses, so a given value is
    classified identically regardless of ingestion path.
    """
    del rules
    text = event.masked_message or ""
    if not text.strip():
        return []

    candidates = candidate_detection_service.detect_text_candidates(
        text, source_location="evidence_text"
    )
    if not candidates:
        return []

    source_type = _source_type_for_event(event)
    findings = exposure_engine.analyse(
        source_type=source_type,
        text=text,
        service=event.service_name,
        endpoint=event.endpoint,
        environment=None,
        event_time=event.timestamp,
        include_suppressed=True,
    )
    # `detect_text_candidates` is called with the same arguments internally by
    # `analyse`, so this local list and the returned findings are positionally
    # aligned 1:1 (deterministic regex candidate detection, no filtering when
    # include_suppressed=True) — this is what lets us recover the raw value
    # for the legacy taxonomy classification side effect below without the
    # engine ever returning a raw value itself.
    mask_spans = [
        MatchSpan(
            start=candidate.start,
            end=candidate.end,
            sensitive_type=candidate.raw_type_hint,
            raw_value=candidate.raw_value,
        )
        for candidate in candidates
        if candidate.start is not None and candidate.end is not None
    ]
    masked_text = masking_service.mask_text(text, mask_spans) if mask_spans else text
    event.masked_message = masked_text

    if len(candidates) != len(findings):
        # Defensive fallback: alignment assumption above did not hold (e.g. a
        # future engine change filters differently). Skip Detection creation
        # rather than risk mismatched sensitive_type/raw_value pairing.
        return []

    detections: list[Detection] = []
    from app.services import privacy_ingestion_pipeline_service

    for candidate, finding in zip(candidates, findings):
        if finding["exposure_decision"] not in _ACTIONABLE_EXPOSURE_DECISIONS:
            continue
        raw_value_hash = fingerprint_for_detection(
            candidate.raw_value,
            finding["sensitive_type"],
            preferred=finding.get("value_fingerprint"),
        )
        existing_detection = db.scalar(
            select(Detection).where(
                Detection.normalized_event_id == event.event_id,
                Detection.sensitive_type == finding["sensitive_type"],
                Detection.raw_value_hash == raw_value_hash,
            ).limit(1)
        )
        if existing_detection is not None:
            continue
        detection = Detection(
            detection_id=generate_detection_id(),
            incident_id=incident_id,
            evidence_id=event.evidence_id,
            normalized_event_id=event.event_id,
            sensitive_type=finding["sensitive_type"],
            raw_value_hash=raw_value_hash,
            masked_value=finding["masked_preview"],
            confidence=finding["confidence_score"],
            severity=severity_for_finding(finding),
            detector_name=exposure_engine.ENGINE_VERSION,
        )
        db.add(detection)
        detections.append(detection)

        # Classify on the pre-mask raw candidate value (never persisted raw) so
        # Nepal-taxonomy matching, fingerprinting, and AML heuristics still run
        # against the real value rather than an already-masked placeholder.
        privacy_ingestion_pipeline_service.classify_and_persist(
            db,
            {finding["sensitive_type"]: candidate.raw_value},
            source_context={
                "endpoint": event.endpoint or "",
                "source_service": event.service_name or "",
            },
            allow_fingerprint=True,
            incident_id=incident_id,
            detection_id=detection.detection_id,
            evidence_id=detection.evidence_id,
            normalized_event_id=event.event_id,
        )

    if detections:
        privacy_ingestion_pipeline_service.refresh_exposure_profiles(
            db,
            incident_id,
            actor_id=None,
        )
        # Phase N: new detection evidence invalidates any existing root-cause
        # analysis ranking for this incident until it is re-run.
        causality_engine.mark_stale(
            db, incident_id, "New detection evidence was added since the last root-cause analysis."
        )
    return detections


def _rule_for_type(rules: list[SensitiveRule], sensitive_type: str) -> SensitiveRule | None:
    for rule in rules:
        if rule.sensitive_type == sensitive_type:
            return rule
    return None


def _has_detections(db: Session, evidence_id: str) -> bool:
    return (
        db.scalar(
            select(Detection.id).where(Detection.evidence_id == evidence_id).limit(1)
        )
        is not None
    )


def list_detections(db: Session, evidence_id: str) -> list[Detection]:
    stmt = (
        select(Detection)
        .where(Detection.evidence_id == evidence_id)
        .order_by(Detection.created_at, Detection.id)
    )
    return list(db.scalars(stmt).all())


def detect_evidence(
    db: Session,
    evidence_id: str,
    *,
    force: bool = False,
) -> DetectEvidenceResult:
    record = db.scalar(
        select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id)
    )
    if not record:
        raise KeyError(f"Evidence not found: {evidence_id}")

    if record.parsing_status != ParsingStatus.PARSED:
        return DetectEvidenceResult(
            evidence_id=evidence_id,
            status="failed",
            error=f"Evidence must be parsed first (status={record.parsing_status.value})",
        )

    if _has_detections(db, evidence_id) and not force:
        count = len(list_detections(db, evidence_id))
        return DetectEvidenceResult(
            evidence_id=evidence_id,
            status="detected",
            detection_count=count,
            skipped=True,
        )


    events = list(
        db.scalars(
            select(NormalizedEvent)
            .where(NormalizedEvent.evidence_id == evidence_id)
            .order_by(NormalizedEvent.timestamp, NormalizedEvent.id)
        ).all()
    )

    rules = load_sensitive_rules()
    total = 0
    warnings: list[str] = []
    affected_incident_ids: set[str] = set()

    try:
        for event in events:
            incident_id = event.linked_incident_id or record.linked_incident_id
            if not incident_id:
                warnings.append(f"skipped event {event.event_id}: no linked incident")
                continue
            created = detect_event(db, event, incident_id=incident_id, rules=rules)
            total += len(created)
            if created:
                affected_incident_ids.add(incident_id)
        if affected_incident_ids:
            from app.schemas.privacy_impact_schema import PrivacyImpactAssessRequest
            from app.services import privacy_impact_service
            for affected_incident_id in sorted(affected_incident_ids):
                privacy_impact_service.assess_incident(
                    db,
                    affected_incident_id,
                    PrivacyImpactAssessRequest(),
                    actor_id=None,
                )
        db.commit()
        return DetectEvidenceResult(
            evidence_id=evidence_id,
            status="detected",
            detection_count=total,
            skipped=False,
            warnings=warnings,
        )
    except Exception as exc:
        db.rollback()
        return DetectEvidenceResult(
            evidence_id=evidence_id,
            status="failed",
            error=str(exc),
            warnings=warnings,
        )


def detect_all_parsed(
    db: Session,
    *,
    linked_incident_id: str | None = None,
) -> DetectAllResult:
    stmt = select(EvidenceFile).where(EvidenceFile.parsing_status == ParsingStatus.PARSED)
    if linked_incident_id:
        stmt = stmt.where(EvidenceFile.linked_incident_id == linked_incident_id)
    stmt = stmt.order_by(EvidenceFile.id)

    records = list(db.scalars(stmt).all())
    batch = DetectAllResult()
    for record in records:
        item = detect_evidence(db, record.evidence_id, force=False)
        batch.results.append(item)
        if not item.skipped and item.status == "detected":
            batch.total_detections += item.detection_count
    return batch
