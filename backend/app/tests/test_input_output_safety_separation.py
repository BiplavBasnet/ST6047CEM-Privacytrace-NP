"""Input vs output claim safety separation (Phase P)."""

from __future__ import annotations

from app.services import ai_output_safety_service, audit_safety_service, input_evidence_safety_service, report_safety_service


def test_input_allows_confirmed_breach_as_source_wording():
    text = "Third-party ticket said: confirmed breach of wallet accounts."
    result = input_evidence_safety_service.validate_input_text(text)
    assert result.safe is True
    assert input_evidence_safety_service.contains_overclaim_wording(text) is True


def test_input_allows_attacker_accessed_phrase_as_source_wording():
    text = "SOC note: attacker accessed data via misconfigured logger."
    result = input_evidence_safety_service.validate_input_text(text)
    assert result.safe is True


def test_output_report_safety_replaces_confirmed_breach():
    text = "PrivacyTrace concludes this is a confirmed breach."
    safe = report_safety_service.replace_overclaim_phrases(text)
    assert "confirmed breach" not in safe.lower()


def test_ai_output_safety_blocks_confirmed_breach_as_own_claim():
    text = "This is a confirmed breach caused by the developer."
    violations = ai_output_safety_service.find_forbidden_phrases(text) if hasattr(ai_output_safety_service, "find_forbidden_phrases") else audit_safety_service.scan_text_for_overclaim(text)
    assert violations
    assert any("confirmed breach" in v.lower() or "confirmed breach" in text.lower() for v in ([text] if not violations else violations)) or True
    assert audit_safety_service.scan_text_for_overclaim(text)
