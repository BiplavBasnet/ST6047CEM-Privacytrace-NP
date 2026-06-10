"""Safety guards for the Guarded LLM Investigation Assistant (Phase 7)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import yaml

from app.config import resolve_rules_dir


@dataclass
class InputGuardResult:
    safe: bool
    violation_codes: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    passed: bool
    errors: list[str] = field(default_factory=list)
    flagged: bool = False
    sanitized_output: dict | None = None


def load_llm_safety_rules() -> dict:
    path = resolve_rules_dir() / "llm_safety_rules.yaml"
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def scan_context_for_leaks(context: dict) -> list[str]:
    rules = load_llm_safety_rules()
    text = json.dumps(context, default=str)
    violations: list[str] = []
    for entry in rules.get("forbidden_input_patterns") or []:
        pattern = entry.get("pattern")
        code = entry.get("code", "forbidden_pattern")
        if pattern and re.search(pattern, text):
            violations.append(code)
    return violations


def validate_input_context(context: dict) -> InputGuardResult:
    violations = scan_context_for_leaks(context)
    return InputGuardResult(safe=not violations, violation_codes=violations)


def validate_output_structure(output: dict) -> list[str]:
    rules = load_llm_safety_rules()
    errors: list[str] = []
    for key in rules.get("required_output_keys") or []:
        if key not in output:
            errors.append(f"missing_output_key:{key}")
    if "safety_notes" in output and not isinstance(output["safety_notes"], dict):
        errors.append("invalid_safety_notes")
    return errors


def _text_blob(output: dict) -> str:
    parts = [
        output.get("incident_summary", ""),
        output.get("likely_cause_explanation", ""),
        output.get("supporting_evidence_summary", ""),
        output.get("recommended_fix_draft", ""),
        output.get("human_review_note", ""),
    ]
    for alt in output.get("alternative_hypotheses") or []:
        if isinstance(alt, dict):
            parts.append(alt.get("hypothesis", ""))
            parts.append(alt.get("confidence_note", ""))
    for q in output.get("missing_evidence_questions") or []:
        parts.append(str(q))
    for item in output.get("fix_verification_checklist") or []:
        parts.append(str(item))
    return "\n".join(parts)


def check_overclaim_phrases(output: dict) -> list[str]:
    rules = load_llm_safety_rules()
    text = _text_blob(output).lower()
    found: list[str] = []
    for phrase in rules.get("overclaim_phrases") or []:
        if phrase.lower() in text:
            found.append(f"overclaim:{phrase}")
    return found


def _has_evidence_reference(text: str, known_ids: set[str]) -> bool:
    if not text:
        return False
    rules = load_llm_safety_rules()
    pattern = rules.get("evidence_id_pattern", r"\b(EVD|LOG|DEPLOY|SAST|DET)-[A-Z0-9-]+\b")
    if re.search(pattern, text, re.IGNORECASE):
        return True
    for eid in known_ids:
        if eid in text:
            return True
    missing_phrases = rules.get("missing_evidence_phrases") or []
    lower = text.lower()
    return any(p.lower() in lower for p in missing_phrases)


def check_evidence_grounding(output: dict, known_evidence_ids: set[str]) -> list[str]:
    errors: list[str] = []
    likely = output.get("likely_cause_explanation", "")
    if likely and not _has_evidence_reference(likely, known_evidence_ids):
        errors.append("likely_cause_missing_evidence_ids")

    for i, alt in enumerate(output.get("alternative_hypotheses") or []):
        if not isinstance(alt, dict):
            continue
        blob = f"{alt.get('hypothesis', '')} {alt.get('confidence_note', '')}"
        ids = alt.get("supporting_evidence_ids") or []
        if blob and not ids and not _has_evidence_reference(blob, known_evidence_ids):
            errors.append(f"alternative_{i}_missing_evidence_ids")
    return errors


def sanitize_overclaims(output: dict) -> dict:
    rules = load_llm_safety_rules()
    replacements = rules.get("safe_replacements") or {}
    result = json.loads(json.dumps(output))

    def _replace_in_str(s: str) -> str:
        out = s
        for bad, good in replacements.items():
            out = re.sub(re.escape(bad), good, out, flags=re.IGNORECASE)
        return out

    for key in (
        "incident_summary",
        "likely_cause_explanation",
        "supporting_evidence_summary",
        "recommended_fix_draft",
        "human_review_note",
    ):
        if key in result and isinstance(result[key], str):
            result[key] = _replace_in_str(result[key])

    for alt in result.get("alternative_hypotheses") or []:
        if isinstance(alt, dict):
            if "hypothesis" in alt:
                alt["hypothesis"] = _replace_in_str(alt["hypothesis"])
            if "confidence_note" in alt:
                alt["confidence_note"] = _replace_in_str(alt["confidence_note"])

    notes = result.setdefault("safety_notes", {})
    notes["contains_overclaiming"] = False
    notes["human_review_required"] = True
    return result


def validate_investigation_output(output: dict, context: dict) -> ValidationResult:
    known_ids = set()
    for item in context.get("masked_evidence") or []:
        if item.get("evidence_id"):
            known_ids.add(str(item["evidence_id"]))
    for rank in context.get("root_cause_ranking") or []:
        for eid in rank.get("supporting_evidence_ids") or []:
            known_ids.add(str(eid))

    errors: list[str] = []
    errors.extend(validate_output_structure(output))
    errors.extend(check_evidence_grounding(output, known_ids))
    overclaims = check_overclaim_phrases(output)

    if overclaims:
        sanitized = sanitize_overclaims(output)
        remaining = check_overclaim_phrases(sanitized)
        if remaining:
            errors.extend(remaining)
            return ValidationResult(passed=False, errors=errors, flagged=True)
        return ValidationResult(
            passed=True,
            errors=overclaims,
            flagged=True,
            sanitized_output=sanitized,
        )

    if errors:
        return ValidationResult(passed=False, errors=errors)

    return ValidationResult(passed=True, errors=[])
