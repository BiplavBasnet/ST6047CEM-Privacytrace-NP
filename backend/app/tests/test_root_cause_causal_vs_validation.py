"""Phase M — causal evidence strength must never be inflated by remediation,
retest, verification, or human review; those only affect a separate
post-remediation validation result.

All tests build `CausalEvidenceInputs`/`ValidationInputs` in memory (no
database) and call the pure `compute_*_from_context` functions directly.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from types import SimpleNamespace

from app.models.enums import EvidenceType, ReviewDecisionType, VerificationStatus
from app.services.root_cause_evidence_strength_service import (
    CausalEvidenceInputs,
    ValidationInputs,
    compute_causal_evidence_strength_from_context,
    compute_post_remediation_validation_from_context,
)


def _incident(**overrides):
    base = {
        "incident_id": "INC-CAUSAL-1",
        "affected_service": "wallet-service",
        "affected_endpoint": "/api/v1/wallet/transfer",
        "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _top_root_cause(**overrides):
    base = {
        "likely_root_cause": "unsafe_request_body_logging",
        "cause_name": "unsafe_request_body_logging",
        "confidence": 0.7,
        "matched_signals": [],
        "negative_signals": [],
        "contradicting_evidence": [],
        "missing_evidence": [],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _cicd_item(evidence_type="deployment_event"):
    return SimpleNamespace(
        cicd_evidence_id="CICD-1",
        evidence_type=evidence_type,
        event_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scan_summary_safe="deployment recorded",
        test_summary_safe=None,
        source_name="ci-runner",
    )


def test_causal_inputs_dataclass_excludes_remediation_review_verification_fields():
    """Structural guarantee: the causal input container cannot even carry
    review/remediation/verification state, so it is impossible for those to
    leak into the causal score by accident."""
    field_names = {f.name for f in dataclasses.fields(CausalEvidenceInputs)}
    for forbidden in ("review", "verification", "remediation_actions", "remediation"):
        assert forbidden not in field_names


def test_causal_strength_unaffected_by_hypothetical_remediation_success():
    """Two identical technical contexts must score identically regardless of
    what later happens during remediation — since compute_causal_evidence_
    strength_from_context never even receives that information."""
    incident = _incident()
    top = _top_root_cause()
    ctx = CausalEvidenceInputs(
        incident=incident,
        detections=[],
        evidence_files=[],
        events=[],
        scanners=[],
        cicd=[_cicd_item()],
        deployments=[],
        sast_count=1,
        top_root_cause=top,
    )
    first = compute_causal_evidence_strength_from_context(ctx)
    # Simulate "time passing" / remediation succeeding: nothing about ctx
    # changes because the dataclass has no such fields to mutate.
    second = compute_causal_evidence_strength_from_context(ctx)
    assert first["causal_strength_score"] == second["causal_strength_score"]
    assert first["causal_confidence_score"] == second["causal_confidence_score"]
    assert first["excludes_post_remediation_evidence"] is True


def test_causal_strength_ignores_missing_retest_language():
    """`missing_evidence` on the top cause may mention retest evidence (a
    validation concern); the causal function must filter that out rather
    than let it affect the causal score/limitations."""
    incident = _incident()
    top = _top_root_cause(missing_evidence=["Missing retest evidence", "Missing code scan finding"])
    ctx = CausalEvidenceInputs(incident=incident, top_root_cause=top)
    result = compute_causal_evidence_strength_from_context(ctx)
    assert not any("retest" in item.lower() for item in result["missing_evidence"])


def test_validation_status_not_started_without_any_post_remediation_evidence():
    incident = _incident()
    ctx = ValidationInputs(incident=incident, top_root_cause=_top_root_cause())
    result = compute_post_remediation_validation_from_context(ctx)
    assert result["validation_status"] == "not_started"
    assert result["remediation_evidence_count"] == 0
    assert result["verification_evidence_count"] == 0
    assert result["review_approved"] is False
    assert result["human_review_required"] is True


def test_validation_reflects_remediation_retest_and_verification_review():
    incident = _incident()
    remediation = SimpleNamespace(
        remediation_action_id="REM-1",
        action_type="code_fix",
        action_description="Redact wallet_id from logs",
        affected_component="wallet_service",
        assigned_owner="dev-team",
        updated_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        status="completed",
    )
    verification = SimpleNamespace(
        id=1,
        verification_status=VerificationStatus.PASSED,
        timestamp=datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    review = SimpleNamespace(decision=ReviewDecisionType.APPROVED.value)
    retest_event = SimpleNamespace(
        evidence_id="EVD-RETEST-1",
        service_name="wallet-service",
        endpoint="/api/v1/wallet/transfer",
    )
    retest_file = SimpleNamespace(evidence_id="EVD-RETEST-1", evidence_type=EvidenceType.FIXED_LOG)

    ctx = ValidationInputs(
        incident=incident,
        remediation_actions=[remediation],
        review=review,
        verification=verification,
        events=[retest_event],
        evidence_files=[retest_file],
        cicd=[],
        top_root_cause=_top_root_cause(),
    )
    result = compute_post_remediation_validation_from_context(ctx)
    assert result["validation_status"] == "verified_passed"
    assert result["remediation_evidence_count"] == 1
    assert result["verification_evidence_count"] == 1
    assert result["verification_passed"] is True
    assert result["review_approved"] is True
    assert result["human_review_required"] is False


def test_causal_score_identical_with_and_without_post_remediation_evidence_present():
    """The core Phase M guarantee: adding remediation/retest/verification/
    review context (as would happen after a fix) must not change the causal
    result, because the causal function is never given that context at all —
    even when the *same* incident later has both computed."""
    incident = _incident()
    top = _top_root_cause()
    causal_ctx = CausalEvidenceInputs(
        incident=incident,
        cicd=[_cicd_item()],
        sast_count=1,
        top_root_cause=top,
    )
    before = compute_causal_evidence_strength_from_context(causal_ctx)

    # Now compute post-remediation validation with a fully "resolved" state —
    # this must be a completely separate call/result and must not be able to
    # feed back into the causal computation above.
    verification = SimpleNamespace(
        id=1, verification_status=VerificationStatus.PASSED, timestamp=datetime.now(timezone.utc)
    )
    review = SimpleNamespace(decision=ReviewDecisionType.APPROVED.value)
    validation_ctx = ValidationInputs(
        incident=incident,
        remediation_actions=[
            SimpleNamespace(
                remediation_action_id="REM-2",
                action_type="code_fix",
                action_description="fix",
                affected_component="wallet_service",
                assigned_owner="dev",
                updated_at=datetime.now(timezone.utc),
                status="completed",
            )
        ],
        review=review,
        verification=verification,
        events=[],
        evidence_files=[],
        cicd=[],
        top_root_cause=top,
    )
    compute_post_remediation_validation_from_context(validation_ctx)

    after = compute_causal_evidence_strength_from_context(causal_ctx)
    assert before["causal_strength_score"] == after["causal_strength_score"]
    assert before["causal_confidence_score"] == after["causal_confidence_score"]
    assert before == after
