"""Sensitive-data exposure policy: presence -> explainable decision.

A detector match only shows a sensitive-looking value was *present*. This
service turns validated candidates into one of the `ExposureDecision`
values by reasoning about where the value was observed (`ExposureLocation`),
its taxonomy category/sensitivity, and any negative signals raised by
`sensitive_value_validation_service`.

Rules are YAML-configurable (`app/rules/exposure_policy_rules.yaml`) so the
policy can evolve without code changes; this module only implements the
matching/precedence logic and always fails closed to `uncertain` rather than
guessing a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import resolve_rules_dir
from app.models.enums import ExposureDecision
from app.services.sensitive_data_taxonomy_service import category_for

DEFAULT_POLICY_VERSION = "exposure_policy_v1"


@dataclass
class PolicyDecision:
    decision: str
    policy_rule_id: str
    policy_version: str
    reason: str
    suppressed_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "policy_rule_id": self.policy_rule_id,
            "policy_version": self.policy_version,
            "reason": self.reason,
            "suppressed_signals": list(self.suppressed_signals),
        }


def _default_path() -> Path:
    return resolve_rules_dir() / "exposure_policy_rules.yaml"


@lru_cache(maxsize=4)
def _load_cached(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"Exposure policy file is malformed: {path.name}")
    return data


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    resolved = Path(path) if path is not None else _default_path()
    return _load_cached(str(resolved.resolve()))


def reset_policy_cache() -> None:
    _load_cached.cache_clear()


def _rule_matches(
    rule: dict[str, Any],
    *,
    category: str,
    sensitivity: str | None,
    exposure_location: str,
    source_type: str | None,
    environment: str | None,
    field_name: str | None,
) -> bool:
    categories = rule.get("categories")
    if categories and category not in categories:
        return False
    sensitivities = rule.get("sensitivity_levels")
    if sensitivities and (sensitivity or "").upper() not in sensitivities:
        return False
    locations = rule.get("exposure_locations")
    if locations and exposure_location not in locations:
        return False
    source_types = rule.get("source_types")
    if source_types and source_type not in source_types:
        return False
    environments = rule.get("environments")
    if environments and environment not in environments:
        return False
    field_name_contains = rule.get("field_name_contains")
    if field_name_contains:
        haystack = (field_name or "").casefold()
        if not any(str(term).casefold() in haystack for term in field_name_contains):
            return False
    return True


def evaluate(
    *,
    taxonomy_type: str,
    sensitivity: str | None = None,
    exposure_location: str,
    source_type: str | None = None,
    field_name: str | None = None,
    environment: str | None = None,
    masking_state: str = "raw",
    negative_signals: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate one validated candidate against the exposure policy.

    Returns a dict with `decision`, `policy_rule_id`, `policy_version`,
    `reason`, and `suppressed_signals`. Never raises for unmatched
    combinations; falls back to `uncertain` so ambiguous cases require human
    review instead of being auto-classified.
    """

    policy = load_policy()
    version = str(policy.get("policy_version") or DEFAULT_POLICY_VERSION)
    negative_signals = list(negative_signals or [])
    negative_signal_set = set(negative_signals)

    hard_suppress = set(policy.get("hard_suppress_signals") or [])
    matched_suppress = sorted(negative_signal_set & hard_suppress)
    if matched_suppress:
        return PolicyDecision(
            decision=ExposureDecision.SUPPRESSED_FALSE_POSITIVE.value,
            policy_rule_id="hard_suppress_signal",
            policy_version=version,
            reason=(
                "Suppressed as a likely false positive: "
                f"{', '.join(matched_suppress)}."
            ),
            suppressed_signals=matched_suppress,
        ).to_dict()

    already_masked_signals = set(policy.get("already_masked_signals") or [])
    if masking_state == "masked" or (negative_signal_set & already_masked_signals):
        return PolicyDecision(
            decision=ExposureDecision.ALREADY_SAFELY_MASKED.value,
            policy_rule_id="already_masked",
            policy_version=version,
            reason="Value already appears masked; not treated as a fresh raw exposure.",
        ).to_dict()

    category = category_for(taxonomy_type).value
    for rule in policy.get("rules") or []:
        if _rule_matches(
            rule,
            category=category,
            sensitivity=sensitivity,
            exposure_location=exposure_location,
            source_type=source_type,
            environment=environment,
            field_name=field_name,
        ):
            return PolicyDecision(
                decision=str(rule["decision"]),
                policy_rule_id=str(rule["id"]),
                policy_version=version,
                reason=str(rule.get("reason") or ""),
            ).to_dict()

    return PolicyDecision(
        decision=ExposureDecision.UNCERTAIN.value,
        policy_rule_id="no_matching_rule",
        policy_version=version,
        reason="No policy rule matched this combination; requires human review.",
    ).to_dict()
