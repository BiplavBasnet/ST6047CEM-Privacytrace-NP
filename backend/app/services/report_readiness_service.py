"""Report readiness derived from real workflow entities."""

from sqlalchemy.orm import Session

from app.models.enums import ReviewDecisionType, VerificationStatus
from app.schemas.report_readiness_schema import (
    ReportReadinessChecks,
    ReportReadinessResponse,
)
from app.services import incident_workflow_service, workflow_provenance_service


def get_report_readiness(db: Session, incident_id: str) -> ReportReadinessResponse:
    facts = incident_workflow_service.collect_workflow_facts(db, incident_id)
    provenance = workflow_provenance_service.get_workflow_provenance_facts(db, incident_id)
    false_positive_chain = bool(
        facts.latest_review is not None
        and facts.latest_review.decision == ReviewDecisionType.REJECTED_FALSE_POSITIVE.value
        and provenance.get("current_root_cause_analysis_id")
        and provenance.get("current_root_cause_analysis_stale") is False
        and facts.latest_review
        and facts.latest_review.root_cause_analysis_id
        == provenance.get("current_root_cause_analysis_id")
        and facts.latest_review.progression_valid
    )
    current_chain = provenance.get("workflow_chain_status") == "current" or false_positive_chain
    root_available = bool(current_chain and facts.root_cause_count and facts.root_strength)
    review_recorded = bool(current_chain and facts.final_review_recorded)
    remediation_recorded = provenance.get("remediation_action_status") in {
        "awaiting_retest",
        "completed",
    }
    implementation_complete = provenance.get("implementation_status") == "completed"
    test_passed = (
        provenance.get("test_execution_status") == "passed"
        and provenance.get("test_execution_id") is not None
    )
    retest_available = provenance.get("controlled_retest_status") == "completed"
    verification_available = (
        str(provenance.get("verification_outcome") or "").casefold()
        == VerificationStatus.PASSED.value
    )
    limitations_available = bool(
        facts.root_strength and facts.root_strength.get("limitations")
    )
    checks = ReportReadinessChecks(
        incident_summary_ready=bool(facts.incident.summary),
        root_cause_available=root_available,
        human_review_recorded=review_recorded,
        remediation_recorded=remediation_recorded,
        retest_evidence_available=retest_available,
        fix_verification_available=verification_available,
        limitations_available=limitations_available,
    )
    blocking: list[str] = []
    if not checks.incident_summary_ready:
        blocking.append("Add an incident summary.")
    if not false_positive_chain:
        blocking.extend(provenance.get("blocked_reasons") or [])
    if not root_available:
        blocking.append("Complete Root Cause & Traceability.")
    if not review_recorded:
        blocking.append("Complete Human Review.")
    latest_decision = facts.latest_review.decision if facts.latest_review else None
    if latest_decision in {
        ReviewDecisionType.REQUEST_MORE_EVIDENCE.value,
        ReviewDecisionType.ESCALATED.value,
        ReviewDecisionType.INCONCLUSIVE.value,
    }:
        blocking.append("Resolve the latest human-review decision.")
    if facts.false_positive:
        blocking = [item for item in blocking if "approved human" not in item.lower()]
    if facts.approved and not remediation_recorded:
        blocking.append("Record a remediation action awaiting retest.")
    if facts.approved and not implementation_complete:
        blocking.append("Record the exact remediation implementation.")
    if facts.approved and not test_passed:
        blocking.append("Run and persist an applicable passed remediation test.")
    if facts.approved and not retest_available:
        blocking.append("Add retest evidence.")
    if facts.approved and not verification_available:
        blocking.append("Run fix verification.")
    if not limitations_available:
        blocking.append("Generate confidence limitations.")
    final_disposition = false_positive_chain or facts.approved
    report_ready = bool(final_disposition and not blocking)
    warnings: list[str] = []
    if facts.approved and not verification_available and provenance.get("verification_outcome"):
        warnings.append(
            "The current verification outcome did not pass; the report must retain that limitation."
        )
    if facts.root_strength and facts.root_strength.get("contradicting_evidence"):
        warnings.append("Contradicting evidence remains in the investigation record.")
    return ReportReadinessResponse(
        incident_id=incident_id,
        report_ready=report_ready,
        draft_report_available=True,
        report_label=(
            "Final report ready"
            if report_ready
            else "Draft report - investigation stages remain incomplete."
        ),
        checks=checks,
        blocking_items=list(dict.fromkeys(blocking)),
        warning_items=warnings,
    )
