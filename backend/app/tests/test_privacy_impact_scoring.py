"""Unit coverage for explainable breach-severity and privacy-harm scoring."""

from __future__ import annotations

import pytest

from app.services.privacy_impact_service import (
    breach_severity_level,
    configured_credential_types,
    load_privacy_impact_rules,
    privacy_harm_level,
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "low"),
        (1.99, "low"),
        (2.0, "medium"),
        (2.99, "medium"),
        (3.0, "high"),
        (3.99, "high"),
        (4.0, "very_high"),
    ],
)
def test_breach_severity_threshold_boundaries(score, expected):
    assert breach_severity_level(score) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1, "low"),
        (3, "low"),
        (4, "medium"),
        (7, "medium"),
        (8, "high"),
        (11, "high"),
        (12, "critical"),
        (16, "critical"),
    ],
)
def test_privacy_harm_threshold_boundaries(score, expected):
    assert privacy_harm_level(score) == expected


def test_enisa_inspired_formula_and_rule_explanations_are_configured():
    rules = load_privacy_impact_rules()
    dpc = rules["data_categories"]["financial_data"]["score"]
    eoi = 0.75
    circumstances = sum(
        rules["circumstances"][code]["score"]
        for code in ("loss_of_confidentiality", "confirmed_exfiltration")
    )
    assert round(dpc * eoi + circumstances, 2) == 3.75
    assert all(item.get("label") for item in rules["data_categories"].values())
    assert all(item.get("label") for item in rules["circumstances"].values())


def test_credential_impact_is_based_on_accessible_system_impact():
    rules = load_privacy_impact_rules()["credential_access_impact"]
    assert rules["limited_service"] < rules["customer_account"]
    assert rules["customer_account"] < rules["financial_account"]
    assert rules["financial_account"] <= rules["privileged_system"]
    assert rules["privileged_system"] == 4.0
    assert {"api_key", "password", "session_token"} <= configured_credential_types()


def test_confidence_concepts_remain_separate():
    assert "assessment_confidence" not in load_privacy_impact_rules()["data_categories"]
    assert breach_severity_level(3.5) == "high"
    assert privacy_harm_level(12) == "critical"
