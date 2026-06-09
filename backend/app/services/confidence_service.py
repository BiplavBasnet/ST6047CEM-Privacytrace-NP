"""Confidence bands and penalty application for root-cause scoring (Phase 6)."""

from __future__ import annotations

import yaml

from app.config import resolve_rules_dir


def load_confidence_rules() -> dict:
    path = resolve_rules_dir() / "confidence_rules.yaml"
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def score_to_band(score: float, rules: dict | None = None) -> str:
    rules = rules or load_confidence_rules()
    bands = rules.get("bands") or {}
    value = max(0.0, min(1.0, score))
    for name in ("high", "medium", "low"):
        band = bands.get(name) or {}
        if band.get("min", 0) <= value <= band.get("max", 1):
            return name
    return "low"


def apply_penalties(
    base_score: float,
    missing_keys: list[str],
    rules: dict | None = None,
) -> tuple[float, list[str]]:
    rules = rules or load_confidence_rules()
    penalties = rules.get("penalties") or {}
    labels: list[str] = []
    score = base_score
    for key in missing_keys:
        entry = penalties.get(key)
        if not entry:
            continue
        score -= float(entry.get("amount", 0))
        label = entry.get("label")
        if label:
            labels.append(label)
    return max(0.0, min(1.0, score)), labels


def format_missing_evidence(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
