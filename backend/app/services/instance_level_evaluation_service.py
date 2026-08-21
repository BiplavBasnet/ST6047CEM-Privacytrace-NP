"""Instance-level evaluation harness for the unified sensitive-data exposure engine.

Historically `evaluation_metric_service.py` measured detection quality by
intersecting *unique sensitive_type sets* (see
`docs/CORE_ENGINE_BASELINE_AUDIT.md` section 7): two log lines each
containing two phone numbers scored identically to one log line containing
one phone number, because both produce the type set ``{"phone_number"}``.
That hides missed or duplicated occurrences.

This module instead evaluates *instances*: each labelled case in
``app/evaluation_data/instance_level_cases.yaml`` declares an ordered list of
expected occurrences (``expected_instances``), and the engine's actual
findings are compared as a multiset per sensitive_type, so two occurrences
must be matched by two findings. See `docs/EVALUATION_DATASET_DESIGN.md` and
`docs/EVALUATION_METHOD.md` for the full method and known simplifications.

This module is pure Python: it calls `sensitive_exposure_engine.analyse()`
directly with no database and no network access, per the project's synthetic
data and no-external-call rules.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.config import resolve_evaluation_data_dir
from app.services import sensitive_exposure_engine as engine

DATASET_FILENAME = "instance_level_cases.yaml"
THESIS_DATASET_FILENAME = "instance_level_cases_v2.yaml"


class EvaluationDatasetError(ValueError):
    """The evaluation dataset file is missing, empty, or malformed."""


@dataclass
class CaseResult:
    case_id: str
    description: str
    label: str
    expected_types: list[str] = field(default_factory=list)
    predicted_types: list[str] = field(default_factory=list)
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    per_type_tp: dict[str, int] = field(default_factory=dict)
    per_type_fp: dict[str, int] = field(default_factory=dict)
    per_type_fn: dict[str, int] = field(default_factory=dict)
    decision_checked: int = 0
    decision_matched: int = 0
    raw_value_checked: bool = False
    raw_value_leaked: bool = False


@dataclass
class InstanceLevelEvaluationResult:
    dataset_version: str
    total_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    per_type_metrics: dict[str, dict[str, float]]
    unsafe_exposure_classification_accuracy: float
    unsafe_exposure_classification_checked: int
    masking_success_rate: float
    raw_sensitive_value_leak_count: int
    case_results: list[CaseResult]

    def as_dict(self) -> dict[str, Any]:
        return {
            "dataset_version": self.dataset_version,
            "total_cases": self.total_cases,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1_score": round(self.f1_score, 6),
            "per_type_metrics": self.per_type_metrics,
            "unsafe_exposure_classification_accuracy": round(
                self.unsafe_exposure_classification_accuracy, 6
            ),
            "unsafe_exposure_classification_checked": self.unsafe_exposure_classification_checked,
            "masking_success_rate": round(self.masking_success_rate, 6),
            "raw_sensitive_value_leak_count": self.raw_sensitive_value_leak_count,
            "case_count": len(self.case_results),
        }


def _dataset_path(path: Path | None = None) -> Path:
    return path or (resolve_evaluation_data_dir() / DATASET_FILENAME)


def load_dataset(path: Path | None = None) -> list[dict[str, Any]]:
    dataset_path = _dataset_path(path)
    if not dataset_path.is_file():
        raise EvaluationDatasetError(f"Evaluation dataset not found: {dataset_path}")
    with dataset_path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationDatasetError(f"Evaluation dataset has no cases: {dataset_path}")
    for case in cases:
        if "case_id" not in case or "source_type" not in case:
            raise EvaluationDatasetError(f"Malformed case (missing case_id/source_type): {case}")
    return cases


def _raw_values_for(case: dict[str, Any]) -> list[str]:
    values: list[str] = []
    single = case.get("raw_value")
    if isinstance(single, str) and single:
        values.append(single)
    many = case.get("raw_values")
    if isinstance(many, list):
        values.extend(str(v) for v in many if v)
    return values


def _run_case(case: dict[str, Any]) -> CaseResult:
    findings = engine.analyse(
        source_type=case["source_type"],
        text=case.get("text"),
        structured=case.get("structured"),
        environment=case.get("environment"),
    )

    expected = list(case.get("expected_instances") or [])
    expected_counter: Counter[str] = Counter(item["sensitive_type"] for item in expected)
    predicted_counter: Counter[str] = Counter(f["sensitive_type"] for f in findings)

    all_types = set(expected_counter) | set(predicted_counter)
    per_type_tp: dict[str, int] = {}
    per_type_fp: dict[str, int] = {}
    per_type_fn: dict[str, int] = {}
    for sensitive_type in all_types:
        expected_count = expected_counter.get(sensitive_type, 0)
        predicted_count = predicted_counter.get(sensitive_type, 0)
        matched = min(expected_count, predicted_count)
        per_type_tp[sensitive_type] = matched
        per_type_fp[sensitive_type] = predicted_count - matched
        per_type_fn[sensitive_type] = expected_count - matched

    decision_checked = 0
    decision_matched = 0
    for item in expected:
        expected_decision = item.get("exposure_decision")
        if not expected_decision:
            continue
        decision_checked += 1
        same_type = [f for f in findings if f["sensitive_type"] == item["sensitive_type"]]
        if any(f.get("exposure_decision") == expected_decision for f in same_type):
            decision_matched += 1

    # Leak check is exact substring only. Regex scanners (audit_safety) false-positive
    # on HMAC fingerprints / masked previews that still match token-shaped patterns.
    raw_values = _raw_values_for(case)
    raw_leaked = False
    if raw_values:
        blob = json.dumps(findings, default=str)
        for raw_value in raw_values:
            if raw_value in blob:
                raw_leaked = True

    return CaseResult(
        case_id=case["case_id"],
        description=str(case.get("description") or ""),
        label=str(case.get("label") or "unspecified"),
        expected_types=[item["sensitive_type"] for item in expected],
        predicted_types=[f["sensitive_type"] for f in findings],
        true_positive=sum(per_type_tp.values()),
        false_positive=sum(per_type_fp.values()),
        false_negative=sum(per_type_fn.values()),
        per_type_tp=per_type_tp,
        per_type_fp=per_type_fp,
        per_type_fn=per_type_fn,
        decision_checked=decision_checked,
        decision_matched=decision_matched,
        raw_value_checked=bool(raw_values),
        raw_value_leaked=raw_leaked,
    )


def _precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def run_instance_level_evaluation(
    path: Path | None = None,
) -> InstanceLevelEvaluationResult:
    """Run every labelled case through the exposure engine and score it.

    Pure function: no database session, no persistence. Callers that want the
    result persisted as `EvaluationMetric` rows should use
    `evaluation_metric_service.run_instance_level_dataset_evaluation`.
    """

    cases = load_dataset(path)
    case_results = [_run_case(case) for case in cases]

    tp = sum(c.true_positive for c in case_results)
    fp = sum(c.false_positive for c in case_results)
    fn = sum(c.false_negative for c in case_results)
    precision, recall, f1 = _precision_recall_f1(tp, fp, fn)

    per_type_totals: dict[str, dict[str, int]] = {}
    for case_result in case_results:
        for sensitive_type in set(case_result.per_type_tp) | set(case_result.per_type_fp) | set(
            case_result.per_type_fn
        ):
            bucket = per_type_totals.setdefault(sensitive_type, {"tp": 0, "fp": 0, "fn": 0})
            bucket["tp"] += case_result.per_type_tp.get(sensitive_type, 0)
            bucket["fp"] += case_result.per_type_fp.get(sensitive_type, 0)
            bucket["fn"] += case_result.per_type_fn.get(sensitive_type, 0)

    per_type_metrics: dict[str, dict[str, float]] = {}
    for sensitive_type, counts in per_type_totals.items():
        p, r, f = _precision_recall_f1(counts["tp"], counts["fp"], counts["fn"])
        per_type_metrics[sensitive_type] = {
            "true_positive": counts["tp"],
            "false_positive": counts["fp"],
            "false_negative": counts["fn"],
            "precision": round(p, 6),
            "recall": round(r, 6),
            "f1_score": round(f, 6),
        }

    decision_checked_total = sum(c.decision_checked for c in case_results)
    decision_matched_total = sum(c.decision_matched for c in case_results)
    unsafe_exposure_accuracy = (
        decision_matched_total / decision_checked_total if decision_checked_total else 0.0
    )

    raw_checked_cases = [c for c in case_results if c.raw_value_checked]
    leaked_cases = [c for c in raw_checked_cases if c.raw_value_leaked]
    masking_success_rate = (
        (len(raw_checked_cases) - len(leaked_cases)) / len(raw_checked_cases)
        if raw_checked_cases
        else 1.0
    )

    version_label = "instance_level_v1"
    if path is not None and "v2" in path.name:
        version_label = "instance_level_v2"
    elif path is None:
        version_label = "instance_level_v1"

    return InstanceLevelEvaluationResult(
        dataset_version=version_label,
        total_cases=len(case_results),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        per_type_metrics=per_type_metrics,
        unsafe_exposure_classification_accuracy=unsafe_exposure_accuracy,
        unsafe_exposure_classification_checked=decision_checked_total,
        masking_success_rate=masking_success_rate,
        raw_sensitive_value_leak_count=len(leaked_cases),
        case_results=case_results,
    )
