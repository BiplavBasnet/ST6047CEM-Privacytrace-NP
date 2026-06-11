"""Unified context-aware sensitive-data exposure engine.

Single pipeline replacing the historically separate Evidence/Live
Monitor/contextual detection paths for the *presence -> exposure decision*
step (see `docs/CORE_ENGINE_BASELINE_AUDIT.md`):

    candidates -> validate -> taxonomy -> infer exposure_location
    -> policy -> confidence -> suppress false positives -> mask
    -> fingerprint (if warranted) -> discard raw value

This module intentionally does not create alerts or persist anything; it
returns plain finding dicts for a caller (a router, a Live Monitor adapter,
or a future unification of `detection_service`/`privacy_ingestion_pipeline_
service`) to act on. No raw value is ever placed on a returned finding.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from app.models.enums import ExposureDecision, ExposureLocation
from app.services import masking_service
from app.services import sensitive_candidate_detection_service as candidate_service
from app.services import sensitive_detection_confidence_service as confidence_service
from app.services import sensitive_exposure_policy_service as policy_service
from app.services import sensitive_fingerprint_service as fingerprint_service
from app.services import sensitive_value_validation_service as validation_service
from app.services.sensitive_candidate_detection_service import SensitiveCandidate
from app.services.sensitive_data_taxonomy_service import (
    TAXONOMY_VERSION,
    category_for,
    sensitivity_for,
)
from app.services.sensitive_value_validation_service import ValidationResult

ENGINE_VERSION = "unified_exposure_engine_v1"

_SOURCE_TYPE_LOCATION_MAP: dict[str, str] = {
    "application_log": ExposureLocation.APPLICATION_LOG.value,
    "runtime_log": ExposureLocation.APPLICATION_LOG.value,
    "log": ExposureLocation.APPLICATION_LOG.value,
    "error_log": ExposureLocation.ERROR_MESSAGE.value,
    "error_message": ExposureLocation.ERROR_MESSAGE.value,
    "query_string": ExposureLocation.QUERY_STRING.value,
    "url_query": ExposureLocation.QUERY_STRING.value,
    "request_header": ExposureLocation.REQUEST_HEADER_PROCESSING.value,
    "request_header_processing": ExposureLocation.REQUEST_HEADER_PROCESSING.value,
    "request_header_log": ExposureLocation.REQUEST_HEADER_LOG.value,
    "request_body": ExposureLocation.REQUEST_BODY.value,
    "response_body": ExposureLocation.RESPONSE_BODY.value,
    "database_field": ExposureLocation.DATABASE_FIELD.value,
    "database": ExposureLocation.DATABASE_FIELD.value,
    "siem_import": ExposureLocation.THIRD_PARTY_LOG.value,
    "third_party_log": ExposureLocation.THIRD_PARTY_LOG.value,
    "scanner_bridge": ExposureLocation.THIRD_PARTY_LOG.value,
    "cache": ExposureLocation.CACHE_ENTRY.value,
    "cache_entry": ExposureLocation.CACHE_ENTRY.value,
    "file_export": ExposureLocation.FILE_EXPORT.value,
    "export": ExposureLocation.FILE_EXPORT.value,
    "webhook": ExposureLocation.WEBHOOK_PAYLOAD.value,
    "webhook_payload": ExposureLocation.WEBHOOK_PAYLOAD.value,
    "ai_prompt": ExposureLocation.AI_PROMPT_CONTEXT.value,
    "ai_prompt_context": ExposureLocation.AI_PROMPT_CONTEXT.value,
}
_VALID_LOCATIONS = {item.value for item in ExposureLocation}

_SAFE_LABEL_RE = re.compile(r"[A-Za-z0-9 _./:\[\]@-]{1,160}")

_FIELD_CONTEXT_REJECT_SIGNALS = {
    "unrelated_field_name",
    "missing_auth_field_context",
    "missing_field_context",
}
_MASKED_NEGATIVE_SIGNALS = {"already_masked_pattern"}

_SAFETY_STATUS_BY_DECISION: dict[str, str] = {
    ExposureDecision.UNSAFE_EXPOSURE.value: "unsafe",
    ExposureDecision.LEGITIMATE_PROCESSING.value: "safe",
    ExposureDecision.ALREADY_SAFELY_MASKED.value: "safe",
    ExposureDecision.UNCERTAIN.value: "requires_review",
    ExposureDecision.SUPPRESSED_FALSE_POSITIVE.value: "suppressed",
}


def _safe_label(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value)
    return text if _SAFE_LABEL_RE.fullmatch(text) else "unclassified"


def _safe_event_time(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def source_type_to_exposure_location(source_type: str | None) -> str | None:
    """Best-effort exposure-location inference from a source/channel name alone.

    Used outside the main `analyse()` pipeline (e.g. by
    `root_cause_exposure_facts_service`) to derive an exposure-location hint
    for already-persisted rows (like `NormalizedEvent`) that only recorded
    `source_type`, without re-running policy/confidence scoring.
    """
    return _SOURCE_TYPE_LOCATION_MAP.get(str(source_type or "").strip().casefold())


def _infer_exposure_location(source_type: str | None, context_metadata: dict[str, Any] | None) -> str:
    context_metadata = context_metadata or {}
    explicit = context_metadata.get("exposure_location")
    if isinstance(explicit, str) and explicit in _VALID_LOCATIONS:
        return explicit
    mapped = _SOURCE_TYPE_LOCATION_MAP.get(str(source_type or "").strip().casefold())
    if mapped == ExposureLocation.REQUEST_HEADER_PROCESSING.value and context_metadata.get("logged"):
        return ExposureLocation.REQUEST_HEADER_LOG.value
    return mapped or ExposureLocation.UNKNOWN.value


def _field_relevance(candidate: SensitiveCandidate, validation: ValidationResult) -> float:
    if set(validation.negative_signals) & _FIELD_CONTEXT_REJECT_SIGNALS:
        return 0.0
    if candidate.field_name:
        return 1.0
    return 0.5


def _masking_state(validation: ValidationResult) -> str:
    if set(validation.negative_signals) & _MASKED_NEGATIVE_SIGNALS:
        return "masked"
    return "raw"


def _new_finding_id() -> str:
    return f"FIND-{uuid.uuid4().hex[:16].upper()}"


def _build_finding(
    candidate: SensitiveCandidate,
    validation: ValidationResult,
    *,
    source_type: str | None,
    exposure_location: str,
    policy_decision: dict[str, Any],
    confidence: confidence_service.ConfidenceResult,
    service: str | None,
    endpoint: str | None,
    environment: str | None,
    event_time: datetime | str | None,
) -> dict[str, Any]:
    category = category_for(candidate.taxonomy_type)
    sensitivity = sensitivity_for(candidate.taxonomy_type)
    decision = policy_decision["decision"]

    masked_preview = masking_service.mask_value(candidate.raw_type_hint, candidate.raw_value)

    value_fingerprint: str | None = None
    fingerprint_method: str | None = None
    fingerprint_version: str | None = None
    if decision != ExposureDecision.ALREADY_SAFELY_MASKED.value:
        try:
            fp = fingerprint_service.fingerprint(candidate.raw_value, candidate.taxonomy_type)
        except fingerprint_service.FingerprintUnavailableError:
            fp = None
        if fp:
            value_fingerprint = fp["fingerprint"]
            fingerprint_method = fp["method"]
            fingerprint_version = fp["version"]

    finding = {
        "finding_id": _new_finding_id(),
        "sensitive_category": category.value,
        "sensitive_type": candidate.taxonomy_type,
        "raw_type_hint": candidate.raw_type_hint,
        "taxonomy_version": TAXONOMY_VERSION,
        "sensitivity_level": sensitivity.value,
        "exposure_location": exposure_location,
        "exposure_decision": decision,
        "policy_rule_id": policy_decision["policy_rule_id"],
        "policy_version": policy_decision["policy_version"],
        "policy_reason": policy_decision["reason"],
        "confidence_score": confidence.score,
        "confidence_level": confidence.level,
        "confidence_breakdown": dict(confidence.breakdown),
        "confidence_engine_version": confidence.engine_version,
        "positive_signals": list(confidence.positive_signals),
        "negative_signals": list(confidence.negative_signals),
        "masked_preview": masked_preview,
        "value_fingerprint": value_fingerprint,
        "fingerprint_method": fingerprint_method,
        "fingerprint_version": fingerprint_version,
        "field_name_safe": _safe_label(candidate.field_name),
        "json_path_safe": _safe_label(candidate.json_path),
        "source_location": candidate.source_location,
        "source_type": source_type,
        "pattern_id": candidate.pattern_id,
        "validator_id": validation.validator_id,
        "detector_version": candidate.detector_version,
        "engine_version": ENGINE_VERSION,
        "service_name": service,
        "endpoint": endpoint,
        "environment": environment,
        "event_time": _safe_event_time(event_time),
        "safety_status": _SAFETY_STATUS_BY_DECISION.get(decision, "requires_review"),
        "limitations": list(validation.limitations),
    }
    assert "raw_value" not in finding
    return finding


def analyse(
    *,
    source_type: str,
    text: str | None = None,
    structured: dict[str, Any] | None = None,
    service: str | None = None,
    endpoint: str | None = None,
    environment: str | None = None,
    event_time: datetime | str | None = None,
    context_metadata: dict[str, Any] | None = None,
    include_suppressed: bool = False,
) -> list[dict[str, Any]]:
    """Run the full unified exposure pipeline and return finding dicts.

    `source_type` names the ingestion/observation channel (e.g.
    "application_log", "request_header", "query_string", "request_body",
    "siem_import"); it drives exposure-location inference and is echoed back
    on findings. `context_metadata` may include an explicit
    `"exposure_location"` override (must be a valid `ExposureLocation`
    value) or `"logged": True` to mark an otherwise in-flight request-header
    observation as having reached a log.

    Findings never include `raw_value`; the raw candidate value is used only
    in-process to validate, mask, and fingerprint before being discarded.
    Candidates the policy suppresses as false positives are dropped from the
    result unless `include_suppressed=True`.
    """

    candidates = candidate_service.detect_candidates(
        text=text,
        structured=structured,
        text_source_location=str(source_type or "text"),
        structured_source_location=str(source_type or "structured_field"),
    )
    exposure_location = _infer_exposure_location(source_type, context_metadata)

    findings: list[dict[str, Any]] = []
    for candidate in candidates:
        validation = validation_service.validate_candidate(
            candidate.raw_value,
            candidate.taxonomy_type,
            {"field_name": candidate.field_name, "json_path": candidate.json_path},
        )
        sensitivity = sensitivity_for(candidate.taxonomy_type)
        masking_state = _masking_state(validation)

        policy_decision = policy_service.evaluate(
            taxonomy_type=candidate.taxonomy_type,
            sensitivity=sensitivity.value,
            exposure_location=exposure_location,
            source_type=source_type,
            field_name=candidate.field_name,
            environment=environment,
            masking_state=masking_state,
            negative_signals=validation.negative_signals,
        )

        confidence = confidence_service.score_confidence(
            pattern_strength=candidate_service.pattern_strength_for(candidate.pattern_id),
            validator_score=validation.validation_score,
            field_relevance=_field_relevance(candidate, validation),
            exposure_location=exposure_location,
            policy_decision=policy_decision["decision"],
            negative_signals=validation.negative_signals,
            positive_signals=validation.positive_signals,
            raw_value=candidate.raw_value,
        )

        if policy_decision["decision"] == ExposureDecision.SUPPRESSED_FALSE_POSITIVE.value and not include_suppressed:
            continue

        findings.append(
            _build_finding(
                candidate,
                validation,
                source_type=source_type,
                exposure_location=exposure_location,
                policy_decision=policy_decision,
                confidence=confidence,
                service=service,
                endpoint=endpoint,
                environment=environment,
                event_time=event_time,
            )
        )

    return findings
