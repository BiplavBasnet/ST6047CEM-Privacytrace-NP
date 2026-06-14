"""Phase L — structured exposure facts feed root-cause scoring.

All tests here build `EvidenceContext`/rows in memory (no database) so they
run without PostgreSQL, matching the existing `test_phase6.py` pattern for
`score_candidate_cause`.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services import causality_engine
from app.services.causality_engine import EvidenceContext, score_candidate_cause
from app.services.root_cause_exposure_facts_service import (
    build_exposure_facts_from_records,
    facts_from_alert,
    fact_from_detection,
    fact_from_finding,
    index_facts_by_type_and_location,
)


def _incident(**overrides):
    base = {"affected_endpoint": "/api/v1/auth/login", "affected_service": "auth-service"}
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# Pure construction helpers (no DB)
# ---------------------------------------------------------------------------


def test_facts_from_alert_extracts_safe_fields():
    alert = SimpleNamespace(
        alert_id="ALERT-1",
        evidence_id="EVD-ALERT-1",
        service_name="auth-service",
        endpoint="/api/v1/auth/login",
        environment="production",
        alert_time="2026-01-01T00:00:00Z",
        alert_findings=[
            {
                "sensitive_type": "bearer_token",
                "exposure_location": "request_header_log",
                "field_name_safe": "authorization",
                "confidence_score": 0.9,
                "exposure_decision": "flagged",
                "deployment_version": "v1.2.3",
                "trace_id": "trace-abc",
            }
        ],
    )
    facts = facts_from_alert(alert)
    assert len(facts) == 1
    fact = facts[0]
    assert fact.sensitive_type == "bearer_token"
    assert fact.exposure_location == "request_header_log"
    assert fact.field_name == "authorization"
    assert fact.service == "auth-service"
    assert fact.endpoint == "/api/v1/auth/login"
    assert fact.environment == "production"
    assert fact.confidence == 0.9
    assert fact.exposure_decision == "flagged"
    assert fact.deployment_version == "v1.2.3"
    assert fact.trace_id == "trace-abc"
    assert fact.evidence_id == "EVD-ALERT-1"
    # No raw value is ever read/stored on a fact.
    assert "raw_value" not in fact.as_dict()


def test_facts_from_alert_ignores_non_dict_findings():
    alert = SimpleNamespace(
        alert_id="ALERT-2",
        evidence_id=None,
        alert_findings=["not-a-dict", None, 42],
    )
    assert facts_from_alert(alert) == []


def test_fact_from_detection_uses_event_for_location_and_trace():
    detection = SimpleNamespace(
        detection_id="DET-1",
        evidence_id="EVD-DET-1",
        sensitive_type="jwt_token",
        confidence=0.8,
    )
    event = SimpleNamespace(
        source_type="application_log",
        deployment_version="v9",
        trace_id="trace-xyz",
        service_name="auth-service",
        endpoint="/api/v1/auth/login",
        timestamp="2026-01-01T00:00:00Z",
    )
    fact = fact_from_detection(detection, event)
    assert fact.sensitive_type == "jwt_token"
    assert fact.deployment_version == "v9"
    assert fact.trace_id == "trace-xyz"
    assert fact.service == "auth-service"
    assert fact.endpoint == "/api/v1/auth/login"
    # `application_log` -> exposure location is inferred via
    # sensitive_exposure_engine.source_type_to_exposure_location.
    assert fact.exposure_location is not None


def test_fact_from_detection_without_event_has_no_location():
    detection = SimpleNamespace(detection_id="DET-2", evidence_id="EVD-DET-2", sensitive_type="phone_number", confidence=0.5)
    fact = fact_from_detection(detection, None)
    assert fact.exposure_location is None
    assert fact.deployment_version is None
    assert fact.trace_id is None


def test_fact_from_finding_maps_engine_finding_dict():
    finding = {
        "finding_id": "FIND-1",
        "sensitive_type": "wallet_identifier",
        "exposure_location": "application_log",
        "field_name_safe": "wallet_id",
        "service_name": "wallet-service",
        "endpoint": "/api/v1/wallet/transfer",
        "environment": "production",
        "confidence_score": 0.75,
        "exposure_decision": "flagged",
        "event_time": "2026-01-01T00:00:00Z",
    }
    fact = fact_from_finding(finding, evidence_id="EVD-FINDING-1")
    assert fact.sensitive_type == "wallet_identifier"
    assert fact.exposure_location == "application_log"
    assert fact.evidence_id == "EVD-FINDING-1"


def test_build_exposure_facts_from_records_aggregates_all_sources():
    alert = SimpleNamespace(
        alert_id="ALERT-3",
        evidence_id="EVD-ALERT-3",
        alert_findings=[{"sensitive_type": "bearer_token", "exposure_location": "request_header_log"}],
    )
    detection = SimpleNamespace(
        detection_id="DET-3",
        evidence_id="EVD-DET-3",
        sensitive_type="jwt_token",
        confidence=0.7,
        normalized_event_id="EVT-3",
    )
    event = SimpleNamespace(
        event_id="EVT-3",
        source_type="api_log",
        deployment_version=None,
        trace_id=None,
        service_name="auth-service",
        endpoint="/api/v1/auth/login",
        timestamp=None,
    )
    finding = {"sensitive_type": "phone_number", "exposure_location": "application_log"}

    facts = build_exposure_facts_from_records(
        alerts=[alert],
        detections=[detection],
        events_by_id={"EVT-3": event},
        findings=[finding],
    )
    assert len(facts) == 3
    sources = {fact.source for fact in facts}
    assert sources == {"alert_finding", "detection", "exposure_finding"}


def test_index_facts_by_type_and_location_groups_and_skips_incomplete():
    alert = SimpleNamespace(
        alert_id="ALERT-4",
        evidence_id="EVD-ALERT-4",
        alert_findings=[
            {"sensitive_type": "bearer_token", "exposure_location": "request_header_log"},
            {"sensitive_type": "bearer_token", "exposure_location": "request_header_log"},
            {"sensitive_type": None, "exposure_location": "request_header_log"},
        ],
    )
    facts = facts_from_alert(alert)
    index = index_facts_by_type_and_location(facts)
    assert index[("bearer_token", "request_header_log")]
    assert len(index[("bearer_token", "request_header_log")]) == 2
    assert len(index) == 1


# ---------------------------------------------------------------------------
# Integration into causality scoring: header-log exposure fact strengthens
# the `authorization_header_logging` candidate (Phase L requirement).
# ---------------------------------------------------------------------------


def _auth_header_rule() -> dict:
    rules = causality_engine.load_root_cause_rules()
    return next(c for c in rules["causes"] if c["likely_root_cause"] == "authorization_header_logging")


def test_exposure_fact_strengthens_request_header_logging_candidate():
    rule = _auth_header_rule()
    base_kwargs = dict(
        incident_id="INC-EXPFACT-1",
        incident=_incident(),
        event_types={"auth_header_logged"},
        masked_messages=["authorization header captured in log"],
        evidence_types_present={"api_log"},
        evidence_ids_by_type={"api_log": ["EVD-API-1"]},
        supporting_evidence_ids={"EVD-API-1"},
    )

    without_facts = EvidenceContext(**base_kwargs, exposure_facts=[])
    with_facts = EvidenceContext(
        **base_kwargs,
        exposure_facts=[
            {
                "fact_id": "ALERTFACT-1",
                "source": "alert_finding",
                "evidence_id": "EVD-API-1",
                "sensitive_type": "bearer_token",
                "exposure_location": "request_header_log",
                "field_name": "authorization",
                "service": "auth-service",
                "endpoint": "/api/v1/auth/login",
                "environment": "production",
                "confidence": 0.9,
                "exposure_decision": "flagged",
                "deployment_version": None,
                "trace_id": None,
                "event_time": None,
            }
        ],
    )

    scored_without = score_candidate_cause(without_facts, rule)
    scored_with = score_candidate_cause(with_facts, rule)

    assert scored_with.final_score > scored_without.final_score
    matched_names = {sig["signal_name"] for sig in scored_with.matched_signals}
    assert "exposure_fact_token_at_header_location" in matched_names
    # Ontology boost should also fire and be transparently recorded.
    ontology_entries = [
        entry
        for entry in scored_with.score_breakdown
        if entry.get("match_type") == "ontology_category_match"
    ]
    assert ontology_entries
    assert ontology_entries[0]["ontology_category_id"] == "unsafe_request_header_logging"
    # Wording must stay at "supports"/"correlates", never "proved caused by".
    for entry in ontology_entries:
        reason = entry["reason"].lower()
        assert "proved caused by" not in reason
        assert "confirmed" not in reason


def test_exposure_fact_wrong_location_does_not_boost_unrelated_candidate():
    rules = causality_engine.load_root_cause_rules()
    dep_rule = next(c for c in rules["causes"] if c["likely_root_cause"] == "suspicious_dependency_introduced")
    ctx = EvidenceContext(
        incident_id="INC-EXPFACT-2",
        incident=_incident(),
        exposure_facts=[
            {
                "fact_id": "ALERTFACT-2",
                "source": "alert_finding",
                "evidence_id": "EVD-API-2",
                "sensitive_type": "bearer_token",
                "exposure_location": "request_header_log",
                "field_name": "authorization",
                "service": None,
                "endpoint": None,
                "environment": None,
                "confidence": 0.9,
                "exposure_decision": "flagged",
                "deployment_version": None,
                "trace_id": None,
                "event_time": None,
            }
        ],
    )
    scored = score_candidate_cause(ctx, dep_rule)
    ontology_entries = [
        entry for entry in scored.score_breakdown if entry.get("match_type") == "ontology_category_match"
    ]
    assert not ontology_entries


def test_build_evidence_context_folds_exposure_facts_shape():
    """EvidenceContext.exposure_facts defaults to empty and accepts dicts as
    produced by `ExposureFact.as_dict()` — sanity check the wiring shape used
    by `build_evidence_context` without requiring a database."""
    ctx = EvidenceContext(incident_id="INC-X", incident=_incident())
    assert ctx.exposure_facts == []
