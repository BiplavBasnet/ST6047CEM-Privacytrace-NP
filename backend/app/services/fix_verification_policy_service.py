"""Incident status transitions after fix verification (Phase 9)."""

from __future__ import annotations

from app.models.enums import IncidentStatus, VerificationStatus
from app.models.incident import Incident


def status_after_verification(verification_status: VerificationStatus) -> IncidentStatus:
    """Central policy: never auto-close incidents."""
    if verification_status == VerificationStatus.PASSED:
        return IncidentStatus.FIXED
    if verification_status == VerificationStatus.FAILED:
        return IncidentStatus.CONFIRMED_INCIDENT
    return IncidentStatus.NEEDS_MORE_EVIDENCE


def apply_verification_status_to_incident(
    incident: Incident, verification_status: VerificationStatus
) -> IncidentStatus:
    new_status = status_after_verification(verification_status)
    incident.status = new_status
    return new_status
