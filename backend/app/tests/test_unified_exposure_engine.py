"""Unit tests for the unified context-aware sensitive-data exposure engine.

These tests exercise pure Python services (taxonomy mapping, candidate
detection, validation, policy, confidence, fingerprinting, and the
`sensitive_exposure_engine.analyse()` pipeline) with no database and no
network access, per the project's synthetic-data and no-external-call evaluation policy.
All secret-looking values below are synthetic placeholders for testing only.
"""

from __future__ import annotations

from app.services import detection_service
from app.services import sensitive_detection_confidence_service as confidence_service
from app.services import sensitive_exposure_engine as engine
from app.services import sensitive_exposure_policy_service as policy_service
from app.services import sensitive_fingerprint_service as fingerprint_service
from app.services import sensitive_value_validation_service as validation_service
from app.services.sensitive_data_taxonomy_service import canonical_type_name

_SYNTHETIC_JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMDAxIn0.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
)


def test_same_value_consistent_taxonomy_mapping():
    first = canonical_type_name("nepal_phone")
    second = canonical_type_name("nepal_phone")
    assert first == second == "phone_number"


def test_legacy_alias_mapping_resolves_to_canonical_type():
    assert canonical_type_name("wallet_id") == "wallet_identifier"
    assert canonical_type_name("authorization_header") == "bearer_token"
    assert canonical_type_name("customer_phone") == "phone_number"
    assert canonical_type_name("completely_unknown_type") == "completely_unknown_type"


def test_nepal_phone_valid_but_timestamp_like_number_rejected():
    valid_phone = validation_service.validate_candidate(
        "9841234567", "phone_number", {"field_name": "phone"}
    )
    assert valid_phone.valid is True
    assert "nepal_prefix_length" in valid_phone.positive_signals

    timestamp_like = validation_service.validate_candidate(
        "1712345678", "phone_number", {"field_name": "contact_number"}
    )
    assert timestamp_like.valid is False
    assert "timestamp_like_number" in timestamp_like.negative_signals


def test_otp_without_auth_context_is_suppressed():
    findings = engine.analyse(
        source_type="request_body",
        structured={"verification_code": "839201"},
    )
    assert findings == []

    findings_with_suppressed = engine.analyse(
        source_type="request_body",
        structured={"verification_code": "839201"},
        include_suppressed=True,
    )
    assert len(findings_with_suppressed) == 1
    decision = findings_with_suppressed[0]["exposure_decision"]
    assert decision in {"suppressed_false_positive", "uncertain"}


def test_luhn_failure_is_suppressed():
    findings = engine.analyse(
        source_type="request_body",
        structured={"card_number": "4111111111111112"},
    )
    assert findings == []


def test_jwt_structure_detected_via_authorization_header_pattern():
    text = f"Authorization: Bearer {_SYNTHETIC_JWT}"
    findings = engine.analyse(source_type="request_header", text=text)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["sensitive_type"] == "bearer_token"
    assert finding["sensitive_category"] == "AUTHENTICATION_SECRET"


def test_already_masked_value_is_not_a_fresh_exposure():
    findings = engine.analyse(
        source_type="database_field",
        structured={"password": "****1234"},
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["exposure_decision"] == "already_safely_masked"
    assert finding["value_fingerprint"] is None
    assert finding["safety_status"] == "safe"


def test_legitimate_processing_versus_unsafe_log_for_same_value():
    text = f"Authorization: Bearer {_SYNTHETIC_JWT}"

    processing_findings = engine.analyse(source_type="request_header", text=text)
    assert len(processing_findings) == 1
    assert processing_findings[0]["exposure_decision"] == "legitimate_processing"

    log_findings = engine.analyse(source_type="application_log", text=text)
    assert len(log_findings) == 1
    assert log_findings[0]["exposure_decision"] == "unsafe_exposure"


def test_confidence_breakdown_is_deterministic():
    kwargs = dict(
        pattern_strength=0.9,
        validator_score=0.85,
        field_relevance=1.0,
        exposure_location="application_log",
        policy_decision="unsafe_exposure",
        negative_signals=[],
        positive_signals=["field_name_support"],
        raw_value="9841234567",
    )
    first = confidence_service.score_confidence(**kwargs)
    second = confidence_service.score_confidence(**kwargs)
    assert first.score == second.score
    assert first.breakdown == second.breakdown
    assert first.level == second.level
    assert 0.0 <= first.score <= 1.0
    assert first.score != 0.92  # not a hardcoded placeholder


def test_confidence_score_reflects_negative_signals():
    base = confidence_service.score_confidence(
        pattern_strength=0.9,
        validator_score=0.9,
        field_relevance=1.0,
        exposure_location="application_log",
        policy_decision="unsafe_exposure",
        negative_signals=[],
        raw_value="9841234567",
    )
    penalised = confidence_service.score_confidence(
        pattern_strength=0.9,
        validator_score=0.9,
        field_relevance=1.0,
        exposure_location="application_log",
        policy_decision="unsafe_exposure",
        negative_signals=["some_negative_signal"],
        raw_value="9841234567",
    )
    assert penalised.score < base.score


def test_hmac_fingerprint_differs_from_legacy_sha256_and_is_deterministic():
    value = "9841234567"
    first = fingerprint_service.fingerprint(value, "phone_number")
    second = fingerprint_service.fingerprint(value, "phone_number")
    assert first["fingerprint"] == second["fingerprint"]
    assert first["method"] == fingerprint_service.FINGERPRINT_METHOD == "hmac_sha256_v1"

    legacy = detection_service.hash_raw_value(value)
    assert fingerprint_service.is_legacy_sha256(legacy) is True
    assert fingerprint_service.is_legacy_sha256(first["fingerprint"]) is False
    assert first["fingerprint"] != legacy


def test_fingerprint_changes_with_taxonomy_type():
    value = "9841234567"
    as_phone = fingerprint_service.fingerprint(value, "phone_number")
    as_generic = fingerprint_service.fingerprint(value, "wallet_identifier")
    assert as_phone["fingerprint"] != as_generic["fingerprint"]


def test_raw_value_never_present_in_finding_output():
    text = (
        f"Authorization: Bearer {_SYNTHETIC_JWT} "
        "customer phone 9841234567 password=SuperSecretValue123"
    )
    findings = engine.analyse(source_type="application_log", text=text)
    assert len(findings) > 0
    for finding in findings:
        assert "raw_value" not in finding
        for value in finding.values():
            if isinstance(value, str):
                assert _SYNTHETIC_JWT not in value
                assert "9841234567" not in value
                assert "SuperSecretValue123" not in value


def test_policy_evaluate_query_string_is_unsafe_regardless_of_category():
    decision = policy_service.evaluate(
        taxonomy_type="phone_number",
        sensitivity="HIGH",
        exposure_location="query_string",
        source_type="query_string",
        field_name="phone",
        environment="production",
        masking_state="raw",
        negative_signals=[],
    )
    assert decision["decision"] == "unsafe_exposure"
    assert decision["policy_rule_id"] == "sensitive_value_in_query_string"


def test_policy_evaluate_defaults_to_uncertain_when_no_rule_matches():
    decision = policy_service.evaluate(
        taxonomy_type="unknown",
        sensitivity="MODERATE",
        exposure_location="unknown",
        source_type="unmapped_channel",
        field_name=None,
        environment="test",
        masking_state="raw",
        negative_signals=[],
    )
    assert decision["decision"] == "uncertain"
    assert decision["policy_rule_id"] == "no_matching_rule"
