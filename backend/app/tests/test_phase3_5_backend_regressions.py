from types import SimpleNamespace

from app.models.enums import EvidenceType
from app.services import (
    ai_provider_client,
    causality_engine,
    counterfactual_analysis_service,
    exposure_profile_service,
    privacy_ingestion_pipeline_service,
    restricted_data_policy_service,
)


def test_restricted_policy_fails_closed_when_internal_flag_is_false():
    records, restricted = restricted_data_policy_service.filter_records(
        [
            {
                "taxonomy_code": "suspicious_activity_flag",
                "internal_only": False,
                "masked_value": "[category-only]",
            }
        ],
        channel="ordinary_api",
    )

    assert restricted is True
    assert records == [
        {
            "taxonomy_code": "restricted_compliance_information",
            "internal_only": True,
            "restricted": True,
        }
    ]


def test_external_payload_sanitizer_removes_nested_restricted_content():
    payload, restricted = restricted_data_policy_service.sanitize_payload(
        {
            "masked_detections": [
                {"sensitive_type": "bank_account_number", "masked_value": "****01"},
                {
                    "sensitive_type": "str_sar_reference",
                    "masked_value": "[category-only]",
                    "internal_only": False,
                },
            ],
            "affected_data_categories": [
                "bank_account_number",
                "aml_investigation_note",
            ],
        },
        channel="external_ai",
    )

    rendered = str(payload).lower()
    assert restricted is True
    assert "bank_account_number" in rendered
    assert "str_sar_reference" not in rendered
    assert "aml_investigation_note" not in rendered


def test_empty_primary_ai_configuration_is_not_attempted(monkeypatch):
    monkeypatch.setattr(
        ai_provider_client,
        "get_settings",
        lambda: SimpleNamespace(
            ai_api_key="",
            ai_backup_api_keys="backup-one,backup-two",
            ai_model="",
            ai_model_candidates="model-one,model-two",
        ),
    )

    assert ai_provider_client.configured_api_keys() == ["backup-one", "backup-two"]
    assert ai_provider_client.configured_models() == ["model-one", "model-two"]


def test_causal_support_and_roles_are_candidate_specific():
    incident = SimpleNamespace(affected_endpoint="/transfer", affected_service="wallet")
    matching = SimpleNamespace(sensitive_type="wallet_identifier", evidence_id="EVD-MATCH")
    unrelated_type = SimpleNamespace(value=EvidenceType.SEMGREP_REPORT.value)
    matching_type = SimpleNamespace(value=EvidenceType.API_LOG.value)
    context = causality_engine.EvidenceContext(
        incident_id="INC-SYNTHETIC",
        incident=incident,
        detections=[matching],
        evidence_files=[
            SimpleNamespace(evidence_id="EVD-MATCH", evidence_type=matching_type),
            SimpleNamespace(evidence_id="EVD-UNRELATED", evidence_type=unrelated_type),
        ],
        sensitive_types={"wallet_identifier"},
        supporting_evidence_ids={"EVD-MATCH", "EVD-UNRELATED"},
    )
    scored = causality_engine.score_candidate_cause(
        context,
        {
            "likely_root_cause": "unsafe_logging",
            "signals": [
                {
                    "name": "wallet data detected",
                    "match": "sensitive_type_present",
                    "value": "wallet_identifier",
                    "weight": 0.7,
                    "reason": "A matching masked detection exists.",
                }
            ],
        },
    )

    assert scored.supporting_evidence_ids == ["EVD-MATCH"]
    assert {item["evidence_id"] for item in scored.evidence_roles} == {"EVD-MATCH"}


def test_counterfactual_selection_uses_one_total_limit():
    selected_supporting, selected_contradictory, selected_unrelated, considered = (
        counterfactual_analysis_service.select_evidence_for_analysis(
            [f"S-{index}" for index in range(20)],
            [f"C-{index}" for index in range(20)],
            [f"U-{index}" for index in range(20)],
            limit=25,
        )
    )

    assert len(considered) == 25
    assert len(selected_supporting) + len(selected_contradictory) + len(selected_unrelated) == 25


def test_counterfactual_fingerprint_changes_with_evidence_content():
    common = {
        "incident_id": "INC-SYNTHETIC",
        "root_cause_id": "RCS-SYNTHETIC",
        "ruleset_version": "rules-v1",
        "baseline_score": 0.7,
        "baseline_rank": 1,
        "matched_signals": [{"signal_name": "signal", "evidence_ids": ["EVD-1"]}],
        "contradicting_evidence": [],
        "considered": ["EVD-1"],
    }
    first = counterfactual_analysis_service.counterfactual_fingerprint(
        **common,
        evidence_state=[
            {"evidence_id": "EVD-1", "evidence_type": "api_log", "file_hash": "hash-one"}
        ],
    )
    second = counterfactual_analysis_service.counterfactual_fingerprint(
        **common,
        evidence_state=[
            {"evidence_id": "EVD-1", "evidence_type": "api_log", "file_hash": "hash-two"}
        ],
    )

    assert first != second


def test_shared_ingestion_pipeline_omits_fingerprint_for_masked_inputs(monkeypatch):
    captured = {}
    sentinel = [SimpleNamespace(taxonomy_code="wallet_identifier")]
    monkeypatch.setattr(
        privacy_ingestion_pipeline_service,
        "get_settings",
        lambda: SimpleNamespace(
            nepal_financial_taxonomy_enabled=True,
            detection_hmac_key="not-observed",
        ),
    )

    def classify(fields, *, source_context, hmac_key):
        captured.update(
            fields=fields,
            source_context=source_context,
            hmac_key=hmac_key,
        )
        return sentinel

    monkeypatch.setattr(
        privacy_ingestion_pipeline_service.contextual_detection_service,
        "classify_structured_fields",
        classify,
    )

    result = privacy_ingestion_pipeline_service.classify_fields(
        {"wallet_identifier": "****01"},
        source_context={"source_service": "wallet"},
        allow_fingerprint=False,
    )

    assert result == sentinel
    assert captured["hmac_key"] == ""


def test_exposure_profiles_without_a_current_candidate_are_retired():
    active = SimpleNamespace(profile_id="EXP-ACTIVE")
    stale = SimpleNamespace(profile_id="EXP-STALE")
    active_key = ("account_takeover", "RULE-1", "subject_reference", "SUBJ-1")
    stale_key = ("aml_exposure", "RULE-2", "evidence", "EVD-1")

    retired = exposure_profile_service.profiles_without_active_candidate(
        {active_key: [active], stale_key: [stale]},
        {active_key},
    )

    assert retired == [stale]
