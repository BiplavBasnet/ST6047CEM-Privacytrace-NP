from app.models.root_cause_score import RootCauseScore
from app.services import causality_engine


def test_root_cause_model_has_traceability_fields():
    for name in (
        "score_breakdown",
        "matched_signals",
        "negative_signals",
        "correlation_reasons",
        "contradicting_evidence",
        "evidence_roles",
        "suggested_actions",
    ):
        assert hasattr(RootCauseScore, name)


def test_rules_include_new_signal_groups():
    rules = causality_engine.load_root_cause_rules()
    assert rules.get("causes")
    assert any("negative_signals" in cause for cause in rules["causes"])
    assert any("contradiction_signals" in cause for cause in rules["causes"])


def test_new_match_types_present_in_rules():
    rules = causality_engine.load_root_cause_rules()
    matches = {
        sig.get("match")
        for cause in rules.get("causes") or []
        for group in ("signals", "negative_signals", "contradiction_signals")
        for sig in (cause.get(group) or [])
    }
    for match in (
        "endpoint_and_service_match",
        "deployment_before_incident_within_minutes",
        "access_event_near_incident_minutes",
        "scanner_same_service",
        "scanner_same_endpoint",
        "raw_reference_matches_any",
        "masked_message_matches_any",
        "evidence_type_absent",
        "event_type_absent",
        "detection_count_at_least",
        "service_or_endpoint_mismatch",
        "old_evidence_outside_time_window",
    ):
        assert match in matches
