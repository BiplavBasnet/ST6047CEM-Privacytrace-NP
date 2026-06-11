"""One deterministic confidence scorer for sensitive-data findings.

Replaces the historical mix of a hardcoded `confidence=0.92` (live alert ->
Detection linking), a raw detector float (`Detection.confidence`), and string
confidence labels (`SensitiveDataClassification.confidence_label`) with a
single explainable 0-1 score plus a breakdown of every contribution.

The score is a deterministic weighted sum of:
  - pattern strength     (regex/rule confidence, or a neutral value for
                           field-alias-only candidates that have no pattern)
  - validator score       (from `sensitive_value_validation_service`)
  - field relevance       (does the field name / json_path support the type?)
  - exposure location     (does the observed location corroborate a real,
                           actionable finding, e.g. a log vs. an unknown
                           channel?)
  - policy modifier       (does the policy decision corroborate or undercut
                           the finding?)
  - entropy               (normalised Shannon entropy of the raw value, only
                           meaningful for credential-like free-form values)
  - negative signal penalty (flat penalty per distinct negative signal)

No branch of this module returns a fixed placeholder score for a taxonomy
type; every output is a function of its inputs, and the same inputs always
produce the same output (deterministic).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

ENGINE_VERSION = "confidence_engine_v1"

_WEIGHT_PATTERN_STRENGTH = 0.30
_WEIGHT_VALIDATOR_SCORE = 0.30
_WEIGHT_FIELD_RELEVANCE = 0.15
_WEIGHT_EXPOSURE_LOCATION = 0.10
_WEIGHT_POLICY_MODIFIER = 0.10
_WEIGHT_ENTROPY = 0.05

_NEGATIVE_SIGNAL_PENALTY = 0.05
_MAX_NEGATIVE_SIGNAL_PENALTY = 0.30

# Locations that make a match more actionable/confidence-worthy to report
# (durable, externally-visible channels) vs. ones that are ambiguous.
_LOCATION_SUPPORT: dict[str, float] = {
    "application_log": 1.0,
    "request_header_log": 1.0,
    "error_message": 1.0,
    "third_party_log": 1.0,
    "file_export": 1.0,
    "webhook_payload": 1.0,
    "ai_prompt_context": 1.0,
    "cache_entry": 0.8,
    "response_body": 0.8,
    "query_string": 0.9,
    "request_body": 0.6,
    "database_field": 0.6,
    "request_header_processing": 0.5,
    "unknown": 0.3,
}

_POLICY_MODIFIER: dict[str, float] = {
    "unsafe_exposure": 1.0,
    "uncertain": 0.4,
    "legitimate_processing": 0.55,
    "already_safely_masked": 0.3,
    "suppressed_false_positive": 0.0,
}

_MAX_ENTROPY_BITS_PER_CHAR = 4.5

_LEVEL_THRESHOLDS: tuple[tuple[str, float], ...] = (
    ("very_high", 0.85),
    ("high", 0.65),
    ("medium", 0.40),
    ("low", 0.0),
)


@dataclass
class ConfidenceResult:
    score: float
    level: str
    breakdown: dict[str, float]
    positive_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_score": self.score,
            "confidence_level": self.level,
            "confidence_breakdown": dict(self.breakdown),
            "confidence_positive_signals": list(self.positive_signals),
            "confidence_negative_signals": list(self.negative_signals),
            "confidence_engine_version": self.engine_version,
        }


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _normalised_entropy(raw_value: str | None) -> float:
    if not raw_value:
        return 0.0
    bits = _shannon_entropy(raw_value)
    return max(0.0, min(1.0, bits / _MAX_ENTROPY_BITS_PER_CHAR))


def _level_for(score: float) -> str:
    for level, threshold in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def score_confidence(
    *,
    pattern_strength: float | None,
    validator_score: float,
    field_relevance: float,
    exposure_location: str,
    policy_decision: str,
    negative_signals: list[str] | None = None,
    positive_signals: list[str] | None = None,
    raw_value: str | None = None,
) -> ConfidenceResult:
    """Score one validated candidate. All inputs are 0-1 unless noted.

    - `pattern_strength`: regex/rule confidence, or `None` for candidates
      found only via a structured field-name alias (treated as a neutral
      0.5 — a name match alone is weaker evidence than a validated pattern).
    - `validator_score`: from `ValidationResult.validation_score`.
    - `field_relevance`: 1.0 if the field/json_path name supports the
      claimed type, 0.5 if neutral/unknown, 0.0 if it contradicts it.
    - `exposure_location`: one of `ExposureLocation` values.
    - `policy_decision`: one of `ExposureDecision` values.
    """

    negative_signals = list(dict.fromkeys(negative_signals or []))
    positive_signals = list(dict.fromkeys(positive_signals or []))

    pattern_component = pattern_strength if pattern_strength is not None else 0.5
    pattern_component = max(0.0, min(1.0, pattern_component))
    validator_component = max(0.0, min(1.0, validator_score))
    field_component = max(0.0, min(1.0, field_relevance))
    location_component = _LOCATION_SUPPORT.get(exposure_location, 0.3)
    policy_component = _POLICY_MODIFIER.get(policy_decision, 0.4)
    entropy_component = _normalised_entropy(raw_value)

    weighted = {
        "pattern_strength": round(pattern_component * _WEIGHT_PATTERN_STRENGTH, 6),
        "validator_score": round(validator_component * _WEIGHT_VALIDATOR_SCORE, 6),
        "field_relevance": round(field_component * _WEIGHT_FIELD_RELEVANCE, 6),
        "exposure_location": round(location_component * _WEIGHT_EXPOSURE_LOCATION, 6),
        "policy_modifier": round(policy_component * _WEIGHT_POLICY_MODIFIER, 6),
        "entropy": round(entropy_component * _WEIGHT_ENTROPY, 6),
    }
    subtotal = sum(weighted.values())

    penalty = min(_MAX_NEGATIVE_SIGNAL_PENALTY, len(negative_signals) * _NEGATIVE_SIGNAL_PENALTY)
    weighted["negative_signal_penalty"] = round(-penalty, 6)

    score = max(0.0, min(1.0, subtotal - penalty))
    return ConfidenceResult(
        score=round(score, 4),
        level=_level_for(score),
        breakdown=weighted,
        positive_signals=positive_signals,
        negative_signals=negative_signals,
    )
