"""Masking service for sensitive values (Phase 5)."""

from __future__ import annotations

from dataclasses import dataclass

import yaml

from app.config import resolve_rules_dir


@dataclass
class MatchSpan:
    start: int
    end: int
    sensitive_type: str
    raw_value: str


def load_masking_rules() -> dict:
    path = resolve_rules_dir() / "masking_rules.yaml"
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("masking") or {}


def mask_value(sensitive_type: str, raw: str) -> str:
    rules = load_masking_rules()
    rule = rules.get(sensitive_type) or rules.get("default") or {}
    strategy = rule.get("strategy", "literal")

    if strategy == "phone_partial":
        keep_prefix = int(rule.get("keep_prefix", 2))
        keep_suffix = int(rule.get("keep_suffix", 2))
        mask_char = rule.get("mask_char", "*")
        if len(raw) <= keep_prefix + keep_suffix:
            return mask_char * len(raw)
        middle_len = len(raw) - keep_prefix - keep_suffix
        return raw[:keep_prefix] + (mask_char * middle_len) + raw[-keep_suffix:]

    return rule.get("masked", "[masked]")


def mask_text(text: str, matches: list[MatchSpan]) -> str:
    if not matches:
        return text
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)), reverse=True)
    result = text
    for match in ordered:
        masked = mask_value(match.sensitive_type, match.raw_value)
        result = result[: match.start] + masked + result[match.end :]
    return result
