"""Phase Q: instance-level evaluation tests.

These tests exercise `instance_level_evaluation_service` and the new
instance-level pieces of `evaluation_metric_service` directly against the
unified exposure engine. Like `test_unified_exposure_engine.py`, they use no
database and no network access (project evaluation policy), so they can run standalone:

    python -m pytest app/tests/test_instance_level_evaluation.py -v

A dedicated PostgreSQL-backed smoke test for the *old* DB-scenario wrapper
lives in `test_phase10_reports_metrics.py`; this file only proves the new
instance-level dataset evaluator and the evidence-faithfulness rewrite are
correct in isolation, plus that the old scenario API surface still exists
(backward compatibility).
"""

from __future__ import annotations

from collections import Counter

import pytest

from app.services import evaluation_metric_service, instance_level_evaluation_service


# ---------------------------------------------------------------------------
# Dataset shape
# ---------------------------------------------------------------------------


def test_dataset_loads_and_covers_required_negative_categories():
    cases = instance_level_evaluation_service.load_dataset()
    case_ids = {c["case_id"] for c in cases}

    # The task brief requires these specific negative-case categories.
    assert "NEG-TIMESTAMP-LIKE-PHONE" in case_ids
    assert "NEG-LUHN-FAIL-CARD" in case_ids
    assert "NEG-ALREADY-MASKED-PASSWORD" in case_ids
    assert any("LEGITIMATE-PROCESSING" in cid for cid in case_ids)
    assert "NEG-OTP-NO-AUTH-CONTEXT" in case_ids

    labels = {c["case_id"]: c.get("label") for c in cases}
    assert labels["NEG-TIMESTAMP-LIKE-PHONE"] == "negative"
    assert labels["POS-PHONE-LOG"] == "positive"


def test_dataset_missing_file_raises_clear_error(tmp_path):
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(instance_level_evaluation_service.EvaluationDatasetError):
        instance_level_evaluation_service.load_dataset(missing)


def test_dataset_empty_cases_raises_clear_error(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("cases: []\n", encoding="utf-8")
    with pytest.raises(instance_level_evaluation_service.EvaluationDatasetError):
        instance_level_evaluation_service.load_dataset(empty)


# ---------------------------------------------------------------------------
# Overall instance-level metrics
# ---------------------------------------------------------------------------


def test_overall_precision_recall_f1_are_perfect_on_curated_dataset():
    result = instance_level_evaluation_service.run_instance_level_evaluation()
    assert result.total_cases >= 15
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1_score == 1.0
    assert result.raw_sensitive_value_leak_count == 0
    assert result.masking_success_rate == 1.0


def test_unsafe_exposure_classification_accuracy_is_measured_and_perfect():
    result = instance_level_evaluation_service.run_instance_level_evaluation()
    # Every positive/negative case with a declared exposure_decision is checked.
    assert result.unsafe_exposure_classification_checked >= 12
    assert result.unsafe_exposure_classification_accuracy == 1.0


def test_per_type_metrics_present_for_each_expected_sensitive_type():
    result = instance_level_evaluation_service.run_instance_level_evaluation()
    expected_types = {
        "phone_number",
        "wallet_identifier",
        "transaction_reference",
        "bearer_token",
        "api_key",
        "private_key",
        "password",
    }
    assert expected_types.issubset(result.per_type_metrics.keys())
    for sensitive_type in expected_types:
        metrics = result.per_type_metrics[sensitive_type]
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0


# ---------------------------------------------------------------------------
# Instance-level vs unique-type-set: the core Phase Q fix
# ---------------------------------------------------------------------------


def test_multi_instance_case_counts_two_true_positives_not_one():
    """POS-PHONE-LOG-MULTI has two phone numbers in one log line.

    A type-set intersection (the old method) would only ever record
    {"phone_number"} regardless of how many times it appears. The new
    instance-level counter must credit two true positives.
    """

    result = instance_level_evaluation_service.run_instance_level_evaluation()
    multi_case = next(c for c in result.case_results if c.case_id == "POS-PHONE-LOG-MULTI")
    assert multi_case.true_positive == 2
    assert multi_case.predicted_types == ["phone_number", "phone_number"]


def test_type_set_intersection_would_hide_the_multi_instance_case():
    """Demonstrates the old (type-set) method's blind spot directly.

    Recomputing the old-style metric on the same case shows precision/recall
    of 1.0 from a *type* perspective even though one of two real occurrences
    could have gone completely undetected without anyone noticing, because
    only set membership was ever checked.
    """

    cases = {c["case_id"]: c for c in instance_level_evaluation_service.load_dataset()}
    case = cases["POS-PHONE-LOG-MULTI"]
    result = instance_level_evaluation_service._run_case(case)  # noqa: SLF001 (test-only introspection)

    expected_type_set = {item["sensitive_type"] for item in case["expected_instances"]}
    predicted_type_set = set(result.predicted_types)
    # Old method: a single missed occurrence would be invisible here.
    assert expected_type_set == predicted_type_set == {"phone_number"}
    # New method: the real occurrence count is visible and correct.
    assert Counter(result.predicted_types)["phone_number"] == 2
    assert result.true_positive == 2


# ---------------------------------------------------------------------------
# Negative cases: no unsafe false positives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_id",
    [
        "NEG-TIMESTAMP-LIKE-PHONE",
        "NEG-LUHN-FAIL-CARD",
        "NEG-OTP-NO-AUTH-CONTEXT",
        "NEG-NO-SENSITIVE-CONTENT",
    ],
)
def test_negative_suppression_cases_produce_no_instances(case_id):
    cases = {c["case_id"]: c for c in instance_level_evaluation_service.load_dataset()}
    result = instance_level_evaluation_service._run_case(cases[case_id])  # noqa: SLF001
    assert result.predicted_types == []
    assert result.false_positive == 0


@pytest.mark.parametrize(
    "case_id,forbidden_decision",
    [
        ("NEG-ALREADY-MASKED-PASSWORD", "unsafe_exposure"),
        ("NEG-LEGITIMATE-PROCESSING-BEARER", "unsafe_exposure"),
        ("NEG-LEGITIMATE-PROCESSING-PASSWORD", "unsafe_exposure"),
    ],
)
def test_safe_but_detected_cases_are_never_classified_unsafe(case_id, forbidden_decision):
    from app.services import sensitive_exposure_engine as engine

    cases = {c["case_id"]: c for c in instance_level_evaluation_service.load_dataset()}
    case = cases[case_id]
    findings = engine.analyse(
        source_type=case["source_type"],
        text=case.get("text"),
        structured=case.get("structured"),
    )
    assert findings, f"{case_id} should still produce a detected instance"
    for finding in findings:
        assert finding["exposure_decision"] != forbidden_decision


# ---------------------------------------------------------------------------
# Evidence faithfulness: supported / unsupported / contradicted
# ---------------------------------------------------------------------------


class _FakeClaim:
    def __init__(self, supporting_evidence_ids=None, contradicting_evidence=None):
        self.supporting_evidence_ids = supporting_evidence_ids
        self.contradicting_evidence = contradicting_evidence


def test_claim_with_empty_supporting_ids_is_unsupported():
    claim = _FakeClaim(supporting_evidence_ids=[], contradicting_evidence=[])
    assert evaluation_metric_service.classify_claim_faithfulness(claim, known_evidence_ids=set()) == "unsupported"


def test_claim_with_fabricated_ids_is_unsupported_even_though_nonempty():
    """The exact regression this phase closes: nonempty IDs must not equal 100%."""

    claim = _FakeClaim(supporting_evidence_ids=["DET-does-not-exist"], contradicting_evidence=[])
    result = evaluation_metric_service.classify_claim_faithfulness(
        claim, known_evidence_ids={"DET-real-one"}
    )
    assert result == "unsupported"


def test_claim_with_resolvable_ids_and_no_contradiction_is_supported():
    claim = _FakeClaim(supporting_evidence_ids=["DET-real-one"], contradicting_evidence=[])
    result = evaluation_metric_service.classify_claim_faithfulness(
        claim, known_evidence_ids={"DET-real-one", "EVD-real-two"}
    )
    assert result == "supported"


def test_claim_with_contradicting_evidence_is_contradicted_even_with_real_support():
    claim = _FakeClaim(
        supporting_evidence_ids=["DET-real-one"],
        contradicting_evidence=[{"evidence_id": "DET-conflict", "reason": "later retest was clean"}],
    )
    result = evaluation_metric_service.classify_claim_faithfulness(
        claim, known_evidence_ids={"DET-real-one"}
    )
    assert result == "contradicted"


def test_claim_with_partially_fabricated_ids_is_unsupported():
    claim = _FakeClaim(
        supporting_evidence_ids=["DET-real-one", "DET-fabricated"],
        contradicting_evidence=[],
    )
    result = evaluation_metric_service.classify_claim_faithfulness(
        claim, known_evidence_ids={"DET-real-one"}
    )
    assert result == "unsupported"


# ---------------------------------------------------------------------------
# evaluation_metric_service wrapper (thin, DB-optional)
# ---------------------------------------------------------------------------


def test_wrapper_returns_same_numbers_as_direct_call():
    direct = instance_level_evaluation_service.run_instance_level_evaluation()
    wrapped = evaluation_metric_service.run_instance_level_dataset_evaluation()
    assert wrapped.precision == direct.precision
    assert wrapped.recall == direct.recall
    assert wrapped.f1_score == direct.f1_score
    assert wrapped.raw_sensitive_value_leak_count == direct.raw_sensitive_value_leak_count


def test_wrapper_requires_db_session_to_persist():
    with pytest.raises(ValueError):
        evaluation_metric_service.run_instance_level_dataset_evaluation(persist=True)


class _FakeSession:
    """Minimal stand-in for a SQLAlchemy Session, DB-free."""

    def __init__(self):
        self.added: list = []

    def add(self, row):
        self.added.append(row)

    def flush(self):
        pass


def test_wrapper_persists_headline_metrics_when_requested():
    fake_db = _FakeSession()
    evaluation_metric_service.run_instance_level_dataset_evaluation(fake_db, persist=True)
    persisted_names = {row.metric_name for row in fake_db.added}
    assert "instance_level_precision" in persisted_names
    assert "instance_level_recall" in persisted_names
    assert "instance_level_f1_score" in persisted_names
    assert "instance_level_raw_sensitive_value_leak_count" in persisted_names
    for row in fake_db.added:
        assert row.scenario_name == "instance_level_dataset_v1"
        assert row.thesis_claim
        assert row.calculation_method


# ---------------------------------------------------------------------------
# Backward compatibility: the old scenario-based API must still exist
# ---------------------------------------------------------------------------


def test_old_scenario_api_surface_is_unchanged():
    assert "scenario_1" in evaluation_metric_service.SCENARIO_GROUND_TRUTH
    assert callable(evaluation_metric_service.compute_metrics_for_scenario)
    assert callable(evaluation_metric_service.run_evaluation)
    assert callable(evaluation_metric_service.list_evaluation_metrics)
    assert "detection_precision" in evaluation_metric_service.CORE_METRIC_NAMES
    assert "evidence_faithfulness_score" in evaluation_metric_service.CORE_METRIC_NAMES
    # New instance-level metric names are additive, not part of the old
    # CORE contract, so old scenario_1 listing behaviour is unaffected.
    assert "instance_level_precision" not in evaluation_metric_service.CORE_METRIC_NAMES
