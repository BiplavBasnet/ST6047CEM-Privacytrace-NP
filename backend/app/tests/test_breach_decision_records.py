from types import SimpleNamespace

import pytest

from app.services.breach_decision_service import (
    BreachDecisionStateError,
    compare_decision_values,
    decision_to_comparable,
    validate_approved_transition,
)


def _decision(decision_id: str, evidence: list[str], severity: str):
    return SimpleNamespace(
        decision_id=decision_id,
        input_evidence_ids=evidence,
        severity_result={"level": severity},
        privacy_harm_result={"level": "medium"},
        containment_recommendations=[],
        customer_notification_recommendation={"recommendation": "not_assessed"},
        uncertainties=["Synthetic evidence only."],
        human_override_present=False,
        human_override_reason=None,
        factors=[
            SimpleNamespace(
                factor_code="public_exposure",
                direction="increases",
                score_contribution=0.5,
                evidence_ids=evidence,
                reason="Synthetic evidence indicates possible public exposure.",
            )
        ],
    )


def test_approved_decision_allows_only_controlled_supersession_transition():
    validate_approved_transition(
        current_status="approved",
        next_status="superseded",
        changed_fields={"status", "superseded_by_record_id"},
    )
    with pytest.raises(BreachDecisionStateError, match="immutable"):
        validate_approved_transition(
            current_status="approved",
            next_status="approved",
            changed_fields={"severity_result"},
        )
    with pytest.raises(BreachDecisionStateError, match="immutable"):
        validate_approved_transition(
            current_status="approved",
            next_status="superseded",
            changed_fields={"status"},
        )


def test_version_difference_keeps_previous_decision_readable_and_explains_change():
    previous = decision_to_comparable(
        _decision("BDR-1", ["EVD-1"], "medium")
    )
    current = decision_to_comparable(
        _decision("BDR-2", ["EVD-1", "EVD-2"], "high")
    )
    difference = compare_decision_values(current, previous)

    assert difference["decision_id"] == "BDR-2"
    assert difference["compared_to_decision_id"] == "BDR-1"
    assert difference["added_evidence"] == ["EVD-2"]
    assert difference["removed_evidence"] == []
    assert difference["changed_fields"]["severity_result"] == {
        "before": {"level": "medium"},
        "after": {"level": "high"},
    }
    assert difference["changed_factors"][0]["factor_code"] == "public_exposure"
