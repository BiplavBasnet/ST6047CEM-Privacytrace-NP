"""Thesis-aligned evaluation metrics (Phase 10)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Detection,
    EvaluationMetric,
    EvidenceFile,
    FixVerification,
    Incident,
    LlmReport,
    ReviewDecision,
    RootCauseScore,
)
from app.models.enums import VerificationStatus
from app.services import audit_safety_service, causality_engine, report_safety_service
from app.services import instance_level_evaluation_service

SCENARIO_GROUND_TRUTH = {
    "scenario_1": {
        "scenario_name": "scenario_1",
        "incident_id": "INC-SEED-001",
        "expected_top_cause": "unsafe_request_body_logging",
        "labelled_sensitive_types": {
            "nepal_phone",
            "wallet_id",
            "transaction_ref",
            "jwt_token",
            "api_key",
            "bearer_token",
        },
        "minimum_expected_types": {
            "nepal_phone",
            "wallet_id",
            "transaction_ref",
        },
    },
}

CORE_METRIC_NAMES = frozenset(
    {
        "detection_precision",
        "detection_recall",
        "detection_f1_score",
        "masking_effectiveness",
        "raw_sensitive_value_leak_count",
        "root_cause_top_1_accuracy",
        "root_cause_top_3_accuracy",
        "evidence_faithfulness_score",
        "llm_overclaim_violation_count",
        "time_to_causal_localisation",
        "fix_verification_success_rate",
        "human_review_completion_rate",
    }
)

METRIC_DEFINITIONS: list[dict] = [
    {
        "metric_name": "detection_precision",
        "thesis_claim": "PrivacyTrace-NP can identify sensitive data exposure.",
        "baseline_name": "basic_scanner",
        "calculation_method": (
            "Type-level precision for labelled scenario: "
            "|detected_types ∩ labelled_types| / |detected_types|."
        ),
        "evidence_source": "detections table vs docs/scenario_ground_truth.md",
    },
    {
        "metric_name": "detection_recall",
        "thesis_claim": (
            "PrivacyTrace-NP can find expected exposed sensitive values in labelled scenarios."
        ),
        "baseline_name": "basic_scanner",
        "calculation_method": (
            "Type-level recall: |detected_types ∩ minimum_expected_types| / "
            "|minimum_expected_types|."
        ),
        "evidence_source": "detections table vs scenario_1 minimum expected types",
    },
    {
        "metric_name": "detection_f1_score",
        "thesis_claim": "Detection performance can be measured against scenario ground truth.",
        "baseline_name": "basic_scanner",
        "calculation_method": "Harmonic mean of detection_precision and detection_recall.",
        "evidence_source": "derived from precision and recall metrics",
    },
    {
        "metric_name": "masking_effectiveness",
        "thesis_claim": "Exposed values are masked before display and reporting.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "Share of detections whose masked_value does not match forbidden raw patterns "
            "in API/report outputs (1.0 = all masked in stored detections)."
        ),
        "evidence_source": "detections.masked_value + audit_safety scan",
    },
    {
        "metric_name": "raw_sensitive_value_leak_count",
        "thesis_claim": "Reports and outputs do not re-expose raw sensitive values.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "Count of forbidden raw pattern matches across detections export and "
            "latest LLM report JSON."
        ),
        "evidence_source": "llm_safety_rules forbidden_input_patterns",
    },
    {
        "metric_name": "root_cause_top_1_accuracy",
        "thesis_claim": "Privacy Causality Engine ranks the correct likely cause first.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "1.0 if rank-1 likely_root_cause equals scenario ground truth, else 0.0."
        ),
        "evidence_source": "root_cause_scores table",
    },
    {
        "metric_name": "root_cause_top_3_accuracy",
        "thesis_claim": "Correct likely cause appears among top ranked causes.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "1.0 if ground-truth cause appears in ranks 1–3, else 0.0."
        ),
        "evidence_source": "root_cause_scores table",
    },
    {
        "metric_name": "evidence_faithfulness_score",
        "thesis_claim": "Explanations and reports are grounded in evidence IDs.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "Share of ranked root-cause claims classified 'supported': every "
            "supporting_evidence_id resolves to a real, incident-scoped "
            "Detection or EvidenceFile record AND the claim has no unresolved "
            "contradicting_evidence. Claims with empty or fabricated "
            "supporting_evidence_ids are 'unsupported'; claims with "
            "contradicting_evidence are 'contradicted'. A non-empty "
            "supporting_evidence_ids list alone is NOT sufficient for a "
            "'supported' classification (see docs/EVALUATION_METHOD.md)."
        ),
        "evidence_source": "root_cause_scores (supporting_evidence_ids, contradicting_evidence) vs detections/evidence_files",
    },
    {
        "metric_name": "llm_overclaim_violation_count",
        "thesis_claim": "Guarded explanation avoids unsupported certainty and blame.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "Count of overclaim phrase matches in latest llm_reports.output_json."
        ),
        "evidence_source": "llm_reports + llm_safety_rules.yaml",
    },
    {
        "metric_name": "time_to_causal_localisation",
        "thesis_claim": (
            "PrivacyTrace-NP reduces time from sensitive data found to likely cause with evidence."
        ),
        "baseline_name": "manual_review",
        "calculation_method": (
            "Seconds between latest detection.created_at and earliest root_cause_scores "
            "created_at for the incident (proxy for detect-all → analyse)."
        ),
        "evidence_source": "detections.created_at, root_cause_scores.created_at",
    },
    {
        "metric_name": "fix_verification_success_rate",
        "thesis_claim": (
            "Fix verification can determine passed, failed or inconclusive retest results."
        ),
        "baseline_name": "manual_review",
        "calculation_method": (
            "Share of fix_verifications with status passed among all verification runs."
        ),
        "evidence_source": "fix_verifications table",
    },
    {
        "metric_name": "human_review_completion_rate",
        "thesis_claim": "Incidents include human review before verification.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "1.0 if at least one approved review_decision exists for the incident, else 0.0."
        ),
        "evidence_source": "review_decisions table",
    },
    {
        "metric_name": "instance_level_precision",
        "thesis_claim": (
            "PrivacyTrace-NP's detection instance count (not just unique types) is precise."
        ),
        "baseline_name": "type_set_intersection",
        "calculation_method": (
            "Instance-level precision across the labelled dataset: for each "
            "case, predicted findings are matched against expected_instances "
            "per sensitive_type as a multiset (min(predicted_count, "
            "expected_count) = true positives); precision = "
            "sum(true_positive) / sum(true_positive + false_positive)."
        ),
        "evidence_source": "app/evaluation_data/instance_level_cases.yaml via sensitive_exposure_engine.analyse()",
    },
    {
        "metric_name": "instance_level_recall",
        "thesis_claim": "PrivacyTrace-NP finds most labelled sensitive-data instances.",
        "baseline_name": "type_set_intersection",
        "calculation_method": "Instance-level recall = sum(true_positive) / sum(true_positive + false_negative).",
        "evidence_source": "app/evaluation_data/instance_level_cases.yaml via sensitive_exposure_engine.analyse()",
    },
    {
        "metric_name": "instance_level_f1_score",
        "thesis_claim": "Instance-level detection performance can be summarised with one score.",
        "baseline_name": "type_set_intersection",
        "calculation_method": "Harmonic mean of instance_level_precision and instance_level_recall.",
        "evidence_source": "derived from instance-level precision and recall",
    },
    {
        "metric_name": "instance_level_unsafe_exposure_classification_accuracy",
        "thesis_claim": (
            "PrivacyTrace-NP distinguishes unsafe exposure from legitimate "
            "processing and already-masked values, not just presence."
        ),
        "baseline_name": "presence_only_scanner",
        "calculation_method": (
            "Share of expected instances with a declared exposure_decision "
            "where a matching-type predicted finding carries that exact "
            "exposure_decision (unsafe_exposure / legitimate_processing / "
            "already_safely_masked / uncertain)."
        ),
        "evidence_source": "app/evaluation_data/instance_level_cases.yaml via sensitive_exposure_engine.analyse()",
    },
    {
        "metric_name": "instance_level_masking_success_rate",
        "thesis_claim": "Detected values are masked before being returned in findings.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "Share of dataset cases with a declared raw_value/raw_values "
            "whose engine findings never contain that raw substring and "
            "trigger no forbidden raw-pattern scan."
        ),
        "evidence_source": "app/evaluation_data/instance_level_cases.yaml raw_value checks",
    },
    {
        "metric_name": "instance_level_raw_sensitive_value_leak_count",
        "thesis_claim": "Findings never re-expose the raw sensitive value that was detected.",
        "baseline_name": "manual_review",
        "calculation_method": (
            "Count of dataset cases where the declared raw_value/raw_values "
            "appeared verbatim in the engine's finding output. Must be 0."
        ),
        "evidence_source": "app/evaluation_data/instance_level_cases.yaml raw_value checks",
    },
]


@dataclass
class MetricRunResult:
    scenario_name: str
    incident_id: str
    metrics: list[EvaluationMetric]


class EvaluationMetricServiceError(Exception):
    pass


class ScenarioNotFoundError(EvaluationMetricServiceError):
    pass


def _definition(name: str) -> dict:
    for item in METRIC_DEFINITIONS:
        if item["metric_name"] == name:
            return item
    raise ScenarioNotFoundError(f"Unknown metric definition: {name}")


def _persist_metric(
    db: Session,
    *,
    scenario_name: str,
    metric_name: str,
    metric_value: float,
) -> EvaluationMetric:
    meta = _definition(metric_name)
    row = EvaluationMetric(
        metric_name=metric_name,
        metric_value=metric_value,
        scenario_name=scenario_name,
        thesis_claim=meta["thesis_claim"],
        baseline_name=meta["baseline_name"],
        calculation_method=meta["calculation_method"],
        evidence_source=meta["evidence_source"],
    )
    db.add(row)
    return row


def _detection_type_metrics(
    db: Session, ground: dict
) -> tuple[float, float, float]:
    incident_id = ground["incident_id"]
    detected = {
        d.sensitive_type
        for d in db.scalars(
            select(Detection).where(Detection.incident_id == incident_id)
        ).all()
    }
    labelled = set(ground["labelled_sensitive_types"])
    minimum = set(ground["minimum_expected_types"])
    tp_labelled = len(detected & labelled)
    precision = tp_labelled / len(detected) if detected else 0.0
    recall = len(detected & minimum) / len(minimum) if minimum else 0.0
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return precision, recall, f1


def _masking_effectiveness(db: Session, incident_id: str) -> float:
    detections = list(
        db.scalars(select(Detection).where(Detection.incident_id == incident_id)).all()
    )
    if not detections:
        return 0.0
    safe_count = 0
    for det in detections:
        blob = json.dumps(
            {
                "masked_value": det.masked_value,
                "sensitive_type": det.sensitive_type,
            }
        )
        if not audit_safety_service.scan_text_for_sensitive(blob):
            safe_count += 1
    return safe_count / len(detections)


def _raw_leak_count(db: Session, incident_id: str) -> float:
    leaks = 0
    detections = db.scalars(
        select(Detection).where(Detection.incident_id == incident_id)
    ).all()
    for det in detections:
        blob = json.dumps({"masked_value": det.masked_value})
        leaks += len(audit_safety_service.scan_text_for_sensitive(blob))
    llm = db.scalar(
        select(LlmReport)
        .where(LlmReport.incident_id == incident_id)
        .order_by(LlmReport.created_at.desc(), LlmReport.id.desc())
        .limit(1)
    )
    if llm:
        from app.services import llm_investigation_service

        llm_out = llm_investigation_service.get_report_output_json(llm)
    else:
        llm_out = None
    if llm_out:
        blob = json.dumps(llm_out)
        leaks += len(audit_safety_service.scan_text_for_sensitive(blob))
        leaks += len(audit_safety_service.scan_text_for_overclaim(blob))
    return float(leaks)


def _root_cause_accuracy(db: Session, ground: dict) -> tuple[float, float]:
    incident_id = ground["incident_id"]
    expected = ground["expected_top_cause"]
    # Phase N: only the incident's current (latest) analysis version counts
    # toward accuracy — a superseded historical batch is not "the" ranking.
    scores = causality_engine.list_root_cause_scores(db, incident_id)
    if not scores:
        return 0.0, 0.0
    top1 = scores[0].likely_root_cause if scores[0].rank == 1 else None
    if top1 is None:
        by_rank = {s.rank: s for s in scores if s.rank is not None}
        top1 = by_rank.get(1).likely_root_cause if 1 in by_rank else scores[0].likely_root_cause
    top3 = {s.likely_root_cause for s in scores if s.rank in (1, 2, 3)}
    top1_acc = 1.0 if top1 == expected else 0.0
    top3_acc = 1.0 if expected in top3 else 0.0
    return top1_acc, top3_acc


def _known_evidence_ids(db: Session, incident_id: str) -> set[str]:
    """Real, incident-scoped evidence identifiers a root-cause claim may cite.

    Deliberately conservative: only identifiers that resolve to a persisted
    `Detection` or `EvidenceFile` row for this incident count as "real". A
    claim citing an ID outside this set is treated as unsupported rather than
    trusted at face value (see docs/EVALUATION_METHOD.md limitations for
    entity types not yet covered, e.g. deployment/scanner evidence IDs).
    """

    detection_ids = set(
        db.scalars(
            select(Detection.detection_id).where(Detection.incident_id == incident_id)
        ).all()
    )
    evidence_ids = set(
        db.scalars(
            select(EvidenceFile.evidence_id).where(
                EvidenceFile.linked_incident_id == incident_id
            )
        ).all()
    )
    return detection_ids | evidence_ids


def classify_claim_faithfulness(claim: RootCauseScore, known_evidence_ids: set[str]) -> str:
    """Classify one ranked root-cause claim as supported/unsupported/contradicted.

    - "contradicted": the claim carries unresolved `contradicting_evidence`.
    - "unsupported": `supporting_evidence_ids` is empty, or cites at least one
      identifier that does not resolve to a real, incident-scoped evidence
      record (a non-empty list is NOT sufficient on its own).
    - "supported": every cited supporting evidence ID resolves to a real
      record and there is no contradicting evidence.
    """

    if list(claim.contradicting_evidence or []):
        return "contradicted"
    supporting = [str(eid) for eid in (claim.supporting_evidence_ids or [])]
    if not supporting:
        return "unsupported"
    if all(eid in known_evidence_ids for eid in supporting):
        return "supported"
    return "unsupported"


def classify_evidence_faithfulness(db: Session, incident_id: str) -> dict:
    """Supported/unsupported/contradicted breakdown across all ranked claims."""

    # Phase N: only the incident's current (latest) analysis version.
    scores = causality_engine.list_root_cause_scores(db, incident_id)
    known_ids = _known_evidence_ids(db, incident_id)
    classifications = [classify_claim_faithfulness(s, known_ids) for s in scores]
    supported = classifications.count("supported")
    unsupported = classifications.count("unsupported")
    contradicted = classifications.count("contradicted")
    total = len(classifications)
    return {
        "total_claims": total,
        "supported_count": supported,
        "unsupported_count": unsupported,
        "contradicted_count": contradicted,
        "faithfulness_score": (supported / total) if total else 0.0,
    }


def _evidence_faithfulness(db: Session, incident_id: str) -> float:
    return classify_evidence_faithfulness(db, incident_id)["faithfulness_score"]


def _llm_overclaim_count(db: Session, incident_id: str) -> float:
    llm = db.scalar(
        select(LlmReport)
        .where(LlmReport.incident_id == incident_id)
        .order_by(LlmReport.created_at.desc(), LlmReport.id.desc())
        .limit(1)
    )
    if not llm:
        return 0.0
    from app.services import llm_investigation_service

    llm_out = llm_investigation_service.get_report_output_json(llm)
    if not llm_out:
        return 0.0
    blob = json.dumps(llm_out)
    return float(
        len(audit_safety_service.scan_text_for_overclaim(blob))
        + len(
            [
                p
                for p in report_safety_service.BLOCKED_OVERCLAIM_EXTRA
                if p in blob.lower()
            ]
        )
    )


def _time_to_causal_localisation(db: Session, incident_id: str) -> float:
    last_detection = db.scalar(
        select(func.max(Detection.created_at)).where(
            Detection.incident_id == incident_id
        )
    )
    first_score = db.scalar(
        select(func.min(RootCauseScore.created_at)).where(
            RootCauseScore.incident_id == incident_id
        )
    )
    if not last_detection or not first_score:
        return 0.0
    delta = first_score - last_detection
    return max(0.0, delta.total_seconds())


def _fix_verification_success_rate(db: Session, incident_id: str) -> float:
    rows = list(
        db.scalars(
            select(FixVerification).where(FixVerification.incident_id == incident_id)
        ).all()
    )
    if not rows:
        return 0.0
    passed = sum(1 for r in rows if r.verification_status == VerificationStatus.PASSED)
    return passed / len(rows)


def _human_review_completion_rate(db: Session, incident_id: str) -> float:
    approved = db.scalar(
        select(ReviewDecision.id)
        .where(ReviewDecision.incident_id == incident_id)
        .where(ReviewDecision.decision == "approved")
        .limit(1)
    )
    return 1.0 if approved else 0.0


def compute_metrics_for_scenario(
    db: Session, scenario_name: str
) -> list[EvaluationMetric]:
    ground = SCENARIO_GROUND_TRUTH.get(scenario_name)
    if not ground:
        raise ScenarioNotFoundError(f"Unknown scenario: {scenario_name}")

    incident_id = ground["incident_id"]
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not incident:
        raise ScenarioNotFoundError(f"Incident not found for scenario: {incident_id}")

    precision, recall, f1 = _detection_type_metrics(db, ground)
    top1, top3 = _root_cause_accuracy(db, ground)

    values: list[tuple[str, float]] = [
        ("detection_precision", precision),
        ("detection_recall", recall),
        ("detection_f1_score", f1),
        ("masking_effectiveness", _masking_effectiveness(db, incident_id)),
        ("raw_sensitive_value_leak_count", _raw_leak_count(db, incident_id)),
        ("root_cause_top_1_accuracy", top1),
        ("root_cause_top_3_accuracy", top3),
        ("evidence_faithfulness_score", _evidence_faithfulness(db, incident_id)),
        ("llm_overclaim_violation_count", _llm_overclaim_count(db, incident_id)),
        ("time_to_causal_localisation", _time_to_causal_localisation(db, incident_id)),
        (
            "fix_verification_success_rate",
            _fix_verification_success_rate(db, incident_id),
        ),
        (
            "human_review_completion_rate",
            _human_review_completion_rate(db, incident_id),
        ),
    ]

    rows: list[EvaluationMetric] = []
    for name, value in values:
        rows.append(
            _persist_metric(
                db,
                scenario_name=scenario_name,
                metric_name=name,
                metric_value=round(value, 6),
            )
        )
    db.flush()
    return rows


def run_evaluation(
    db: Session,
    *,
    scenario_name: str = "scenario_1",
    requested_by: int | None = None,
) -> MetricRunResult:
    ground = SCENARIO_GROUND_TRUTH.get(scenario_name)
    if not ground:
        raise ScenarioNotFoundError(f"Unknown scenario: {scenario_name}")

    metrics = compute_metrics_for_scenario(db, scenario_name)
    db.commit()
    for row in metrics:
        db.refresh(row)

    return MetricRunResult(
        scenario_name=scenario_name,
        incident_id=ground["incident_id"],
        metrics=metrics,
    )


def list_evaluation_metrics(
    db: Session,
    *,
    scenario_name: str | None = None,
    latest_only: bool = True,
) -> list[EvaluationMetric]:
    stmt = select(EvaluationMetric).order_by(
        EvaluationMetric.created_at.desc(), EvaluationMetric.id.desc()
    )
    if scenario_name:
        stmt = stmt.where(EvaluationMetric.scenario_name == scenario_name)
    rows = list(db.scalars(stmt).all())
    if not latest_only:
        return rows
    seen: set[str] = set()
    latest: list[EvaluationMetric] = []
    for row in rows:
        if row.metric_name in seen:
            continue
        if row.metric_name not in CORE_METRIC_NAMES:
            continue
        seen.add(row.metric_name)
        latest.append(row)
    return latest


def run_instance_level_dataset_evaluation(
    db: Session | None = None,
    *,
    persist: bool = False,
    dataset_path: Path | None = None,
) -> instance_level_evaluation_service.InstanceLevelEvaluationResult:
    """Run the Phase Q instance-level labelled dataset through the exposure engine.

    Pure and database-free by default: this always recomputes the metrics
    from `sensitive_exposure_engine.analyse()` against
    `app/evaluation_data/instance_level_cases.yaml`; it never returns a
    manufactured or cached number. Pass a session with `persist=True` to also
    store the headline metrics as `EvaluationMetric` rows (scenario_name
    ``instance_level_dataset_v1``) for audit history alongside the older
    scenario-based metrics.

    This is additive: it does not change `compute_metrics_for_scenario`,
    `run_evaluation`, or `list_evaluation_metrics`, which remain the
    backward-compatible API for the existing DB-scenario evaluation.
    """

    result = instance_level_evaluation_service.run_instance_level_evaluation(dataset_path)
    if persist:
        if db is None:
            raise ValueError("db session is required when persist=True")
        values: list[tuple[str, float]] = [
            ("instance_level_precision", result.precision),
            ("instance_level_recall", result.recall),
            ("instance_level_f1_score", result.f1_score),
            (
                "instance_level_unsafe_exposure_classification_accuracy",
                result.unsafe_exposure_classification_accuracy,
            ),
            ("instance_level_masking_success_rate", result.masking_success_rate),
            (
                "instance_level_raw_sensitive_value_leak_count",
                float(result.raw_sensitive_value_leak_count),
            ),
        ]
        for name, value in values:
            _persist_metric(
                db,
                scenario_name="instance_level_dataset_v1",
                metric_name=name,
                metric_value=round(value, 6),
            )
        db.flush()
    return result


def build_unsafe_report_probe() -> dict:
    """Test-only payload that must be rejected by report safety."""
    return {
        "incident_id": "UNSAFE-PROBE",
        "title": "probe",
        "masked_detections": [{"masked_value": "9841234567"}],
        "safety_statement": "probe",
    }
