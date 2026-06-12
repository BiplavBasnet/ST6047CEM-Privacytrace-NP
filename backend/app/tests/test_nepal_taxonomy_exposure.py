from app.schemas.exposure_profile_schema import ClassificationFact
from app.services.contextual_detection_service import classify_structured_fields
from app.services.exposure_profile_service import evaluate_exposure_profiles, load_rules
from app.services.taxonomy_registry_service import load_taxonomy


def _fact(classification_id: str, code: str, group: str, *, subject: str = "SUBJ-HMAC-1", credential_status: str | None = None, internal_only: bool = False) -> ClassificationFact:
    return ClassificationFact(
        classification_id=classification_id,
        taxonomy_code=code,
        taxonomy_version="np-dfs-1.0.0",
        category_group=group,
        affected_subject_reference_id=subject,
        credential_status=credential_status,
        confidence_label="validated",
        internal_only=internal_only,
    )


def test_taxonomy_covers_all_eight_financial_data_areas():
    registry = load_taxonomy()
    assert registry.version == "np-dfs-1.0.0"
    assert {item["group"] for item in registry.enabled_categories()} == {
        "identity",
        "kyc_document",
        "financial_account",
        "payment_card",
        "authentication_credential",
        "transaction",
        "restricted_aml",
        "merchant_kyc",
    }


def test_contextual_detector_masks_values_across_all_eight_areas():
    fields = {
        "citizenship_no": "SYNTH-CIT-001",
        "citizenship_scan": "synthetic-document-reference",
        "bank_account_number": "SYNTH-ACCOUNT-001",
        "card_number": "4111111111111111",
        "password": "SyntheticPasswordOnly",
        "transaction_id": "SYNTH-TXN-001",
        "suspicious_activity_flag": "synthetic-review-only",
        "merchant_api_key": "synthetic-merchant-key",
    }
    results = classify_structured_fields(fields, source_context={"endpoint": "/synthetic-test", "document_type": "synthetic"}, hmac_key="synthetic-test-hmac-key")
    assert {item.category_group for item in results} == {
        "identity",
        "kyc_document",
        "financial_account",
        "payment_card",
        "authentication_credential",
        "transaction",
        "restricted_aml",
        "merchant_kyc",
    }
    rendered = " ".join(item.masked_value for item in results)
    assert "SyntheticPasswordOnly" not in rendered
    assert "4111111111111111" not in rendered
    assert all(item.value_fingerprint is None or item.value_fingerprint.startswith("HMAC-SHA256-V1:") for item in results)


def test_combination_rules_build_account_takeover_and_internal_aml_profiles():
    ruleset = load_rules()
    facts = [
        _fact("CLS-1", "bank_account_number", "financial_account"),
        _fact("CLS-2", "plaintext_password", "authentication_credential", credential_status="unknown"),
        _fact("CLS-3", "suspicious_activity_flag", "restricted_aml", subject="SUBJ-HMAC-2", internal_only=True),
    ]
    profiles = evaluate_exposure_profiles(facts, ruleset=ruleset)
    account = next(item for item in profiles if item.profile_type == "account_takeover_risk")
    aml = next(item for item in profiles if item.profile_type == "aml_confidentiality_exposure")
    assert account.severity == "critical"
    assert account.customer_notification_allowed is True
    assert aml.internal_only is True
    assert aml.customer_notification_allowed is False

