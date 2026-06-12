from __future__ import annotations

from app.models.enums import EvidenceType
from app.schemas.final_report_schema import FinalInvestigationReport
from app.services.final_report_pdf_service import render_final_report_pdf
from app.services.final_report_service import (
    derive_evidence_strength,
    final_report_to_json,
    render_final_report_html,
)


def test_live_and_log_symptom_evidence_stays_weak() -> None:
    live_only, missing = derive_evidence_strength([], has_live_alert=True)
    logs_only, _ = derive_evidence_strength(
        [EvidenceType.API_LOG, EvidenceType.SIEM_ALERT]
    )

    assert live_only == "weak"
    assert logs_only == "weak"
    assert any("CI/CD" in item for item in missing)


def test_evidence_strength_requires_technical_and_retest_diversity() -> None:
    strong, strong_missing = derive_evidence_strength(
        [EvidenceType.API_LOG, EvidenceType.DEPLOYMENT_LOG],
        has_live_alert=True,
    )
    very_strong, complete_missing = derive_evidence_strength(
        [
            EvidenceType.SIEM_ALERT,
            EvidenceType.SEMGREP_REPORT,
            EvidenceType.FIXED_LOG,
        ],
        has_live_alert=True,
    )

    assert strong == "strong"
    assert any("retest" in item for item in strong_missing)
    assert very_strong == "very strong"
    assert complete_missing == []


def _live_report() -> FinalInvestigationReport:
    return FinalInvestigationReport.model_validate(
        {
            "metadata": {
                "incident_id": "INC-LIVE-REPORT",
                "generated_at": "2026-07-13T10:00:00Z",
                "generated_by": "test",
                "system_version": "test",
                "report_format": "html",
            },
            "executive_summary": {
                "incident_summary": "Possible masked privacy exposure.",
                "affected_service": "wallet-service",
                "affected_endpoint": "/wallet/transfer",
                "severity": "high",
                "top_likely_cause": "logging configuration may need review",
                "confidence_band": "low",
                "human_review_status": "pending - human review required",
                "fix_verification_status": "not completed",
            },
            "incident": {
                "incident_id": "INC-LIVE-REPORT",
                "title": "Possible privacy exposure",
                "status": "new",
                "severity": "high",
            },
            "live_monitor_summary": {
                "source": "Live Monitor",
                "linked_alert_count": 1,
                "evidence_strength": "weak",
                "missing_evidence": ["CI/CD deployment, code/config or scanner evidence"],
                "evidence_source_summary": {"SIEM alert evidence": 1},
                "alert_to_incident_flow": "1 masked privacy alert was linked to the incident.",
                "limitations": ["Live alert evidence alone cannot establish cause."],
                "alerts": [
                    {
                        "alert_id": "LPA-REPORT-001",
                        "alert_time": "2026-07-13T09:59:00Z",
                        "first_seen": "2026-07-13T09:59:00Z",
                        "last_seen": "2026-07-13T09:59:01Z",
                        "repeat_count": 1,
                        "source_type": "api_log",
                        "source_name": "wallet-service",
                        "service_name": "wallet-service",
                        "endpoint": "/wallet/transfer",
                        "severity": "high",
                        "status": "linked_to_incident",
                        "sensitive_types": ["nepal_phone"],
                        "masked_values": ["984****567"],
                        "evidence_id": "EVD-LIVE-001",
                    }
                ],
            },
            "guarded_explanation": {
                "human_review_required": True,
                "not_generated_message": "Human review required.",
            },
            "human_review": {
                "not_completed_message": "Human review has not yet been completed."
            },
            "fix_verification": {
                "not_completed_message": "Fix verification has not yet been completed."
            },
            "remediation_actions": [
                "No separate reviewer-accepted remediation action record was available."
            ],
            "privacy_safety_controls": ["Masked values only."],
            "limitations": ["Available evidence may be incomplete."],
        }
    )


def test_final_report_renders_live_monitor_flow_safely() -> None:
    report = _live_report()
    html = render_final_report_html(report)
    json_text = final_report_to_json(report)
    pdf = render_final_report_pdf(report)

    for output in (html, json_text):
        assert "Live Monitor" in output
        assert "LPA-REPORT-001" in output
        assert "984****567" in output
        assert "9841234567" not in output
        assert "guaranteed fixed" not in output.lower()
        assert "proven root cause" not in output.lower()
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000
