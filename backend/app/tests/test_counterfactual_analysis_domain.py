from app.services.counterfactual_analysis_service import (
    MAX_EVIDENCE_ITEMS,
    classify_importance,
    classify_stability,
)


def _result(change, *, rank_changed=False, test_type="evidence_removal"):
    return {
        "score_change": change,
        "rank_changed": rank_changed,
        "test_type": test_type,
    }


def test_counterfactual_stability_levels_are_explainable():
    assert (
        classify_stability(
            baseline_score=0.0, supporting_count=0, results=[]
        )
        == "insufficient_evidence"
    )
    assert (
        classify_stability(
            baseline_score=0.7,
            supporting_count=2,
            results=[_result(0.01), _result(0.02)],
        )
        == "stable"
    )
    assert (
        classify_stability(
            baseline_score=0.7,
            supporting_count=2,
            results=[_result(0.08)],
        )
        == "moderately_stable"
    )
    assert (
        classify_stability(
            baseline_score=0.7,
            supporting_count=2,
            results=[_result(0.01, rank_changed=True)],
        )
        == "fragile"
    )


def test_evidence_roles_do_not_overstate_unrelated_or_contradictory_items():
    assert (
        classify_importance(
            score_change=0.0,
            rank_changed=False,
            test_type="unrelated_removal",
        )
        == "irrelevant"
    )
    assert (
        classify_importance(
            score_change=-0.2,
            rank_changed=False,
            test_type="contradiction_removal",
        )
        == "contradictory"
    )
    assert (
        classify_importance(
            score_change=0.3,
            rank_changed=False,
            test_type="evidence_removal",
        )
        == "strong_support"
    )
    assert MAX_EVIDENCE_ITEMS == 25
