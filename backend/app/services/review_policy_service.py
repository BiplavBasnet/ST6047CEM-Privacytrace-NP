"""Central review decision parsing and incident status mapping (Phase 8 hardening)."""

from __future__ import annotations

from app.models.enums import IncidentStatus, ReviewDecisionType

_DECISION_TO_STATUS: dict[ReviewDecisionType, IncidentStatus] = {
    ReviewDecisionType.APPROVED: IncidentStatus.CONFIRMED_INCIDENT,
    ReviewDecisionType.REJECTED: IncidentStatus.FALSE_POSITIVE,
    ReviewDecisionType.REJECTED_FALSE_POSITIVE: IncidentStatus.FALSE_POSITIVE,
    ReviewDecisionType.INCONCLUSIVE: IncidentStatus.UNDER_REVIEW,
    ReviewDecisionType.REQUEST_MORE_EVIDENCE: IncidentStatus.NEEDS_MORE_EVIDENCE,
    ReviewDecisionType.ESCALATED: IncidentStatus.UNDER_REVIEW,
}

_ALLOWED_CANONICAL = {d.value for d in ReviewDecisionType}


class InvalidReviewDecisionError(ValueError):
    """Review decision is not one of the four allowed values."""


def parse_review_decision(value: str) -> ReviewDecisionType:
    """Parse and validate a review decision; rejects unknown values."""
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "approve": ReviewDecisionType.APPROVED,
        "approved": ReviewDecisionType.APPROVED,
        "reject": ReviewDecisionType.REJECTED,
        "rejected": ReviewDecisionType.REJECTED,
        "rejected_false_positive": ReviewDecisionType.REJECTED_FALSE_POSITIVE,
        "decline_as_false_positive": ReviewDecisionType.REJECTED_FALSE_POSITIVE,
        "inconclusive": ReviewDecisionType.INCONCLUSIVE,
        "request_more_evidence": ReviewDecisionType.REQUEST_MORE_EVIDENCE,
        "needs_more_evidence": ReviewDecisionType.REQUEST_MORE_EVIDENCE,
        "escalated": ReviewDecisionType.ESCALATED,
        "escalate": ReviewDecisionType.ESCALATED,
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized in _ALLOWED_CANONICAL:
        return ReviewDecisionType(normalized)
    raise InvalidReviewDecisionError(
        f"Invalid review decision: {value}. "
        f"Allowed: {', '.join(sorted(_ALLOWED_CANONICAL))}"
    )


def map_review_decision_to_status(decision: ReviewDecisionType) -> IncidentStatus:
    """Map a validated review decision to the incident workflow status."""
    try:
        return _DECISION_TO_STATUS[decision]
    except KeyError as exc:
        raise InvalidReviewDecisionError(
            f"No status mapping for decision: {decision.value}"
        ) from exc
