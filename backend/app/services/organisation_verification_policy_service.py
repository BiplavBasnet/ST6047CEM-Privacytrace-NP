"""Authoritative organisation verification policy (single gate)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import MembershipStatus, OrganisationStatus, OrganisationVerificationStatus, UserRole
from app.models.organisation import DeploymentSetup, Organisation, OrganisationMembership
from app.models.user import User
from app.services import pan_verification_service


class OrganisationVerificationPolicyError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def _is_verified(status: OrganisationVerificationStatus | str) -> bool:
    value = status.value if isinstance(status, OrganisationVerificationStatus) else str(status)
    return value == OrganisationVerificationStatus.VERIFIED.value


def policy_requirements_met(org: Organisation) -> bool:
    if not _is_verified(org.legal_verification_status):
        return False
    if not _is_verified(org.domain_verification_status):
        return False
    if not _is_verified(org.admin_email_verification_status):
        return False
    if pan_verification_service.pan_verification_required():
        if not _is_verified(org.pan_verification_status):
            return False
    return True


def compute_overall_status(org: Organisation) -> OrganisationVerificationStatus:
    if org.overall_verification_status == OrganisationVerificationStatus.REJECTED:
        return OrganisationVerificationStatus.REJECTED
    if org.overall_verification_status == OrganisationVerificationStatus.SUSPENDED:
        return OrganisationVerificationStatus.SUSPENDED
    # MANUAL_REVIEW stays until Platform Operator decides — no soft auto-verify.
    if org.overall_verification_status == OrganisationVerificationStatus.MANUAL_REVIEW:
        return OrganisationVerificationStatus.MANUAL_REVIEW
    if policy_requirements_met(org):
        return OrganisationVerificationStatus.VERIFIED

    statuses = [
        org.legal_verification_status,
        org.domain_verification_status,
        org.admin_email_verification_status,
    ]
    if pan_verification_service.pan_verification_required():
        statuses.append(org.pan_verification_status)
    if any(s == OrganisationVerificationStatus.MANUAL_REVIEW for s in statuses):
        return OrganisationVerificationStatus.MANUAL_REVIEW
    if any(_is_verified(s) for s in statuses):
        return OrganisationVerificationStatus.PARTIALLY_VERIFIED
    if any(s == OrganisationVerificationStatus.PENDING_VERIFICATION for s in statuses):
        return OrganisationVerificationStatus.PENDING_VERIFICATION
    return OrganisationVerificationStatus.PENDING_VERIFICATION


def organisation_is_operationally_verified(org: Organisation) -> bool:
    return _is_verified(org.overall_verification_status)


def activate_verified_organisation(
    db: Session,
    org: Organisation,
    *,
    actor_id: int | None,
    notes_safe: str | None = None,
) -> OrganisationMembership | None:
    """Activate first pending org admin and permanently lock deployment setup."""
    if not policy_requirements_met(org) and org.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
        raise OrganisationVerificationPolicyError("Verification policy not satisfied")

    now = datetime.now(UTC)
    org.overall_verification_status = OrganisationVerificationStatus.VERIFIED
    if not org.overall_verification_method:
        if org.demo_verification_simulated or org.verification_mode == "demo":
            org.overall_verification_method = "DEMO_SIMULATED"
        elif actor_id is not None:
            org.overall_verification_method = "MANUAL_OPERATOR"
        else:
            org.overall_verification_method = "DNS_TXT"
    org.status = OrganisationStatus.ACTIVE
    org.verified_at = now
    if actor_id is not None:
        org.verified_by = actor_id
    if notes_safe:
        org.verification_notes_safe = notes_safe[:2000]

    membership = db.scalar(
        select(OrganisationMembership)
        .where(
            OrganisationMembership.organisation_id == org.id,
            OrganisationMembership.role.in_((UserRole.ORGANISATION_ADMIN, UserRole.ADMIN)),
            OrganisationMembership.status == MembershipStatus.PENDING,
        )
        .order_by(OrganisationMembership.id.asc())
        .limit(1)
    )
    if membership is not None:
        membership.status = MembershipStatus.ACTIVE
        membership.approved_at = now
        membership.approved_by = actor_id or membership.user_id
        user = db.get(User, membership.user_id)
        if user is not None:
            user.is_active = True

    setup = db.get(DeploymentSetup, 1)
    if setup is None:
        setup = DeploymentSetup(id=1)
        db.add(setup)
    setup.completed = True
    setup.completed_at = now
    setup.completed_by_user_id = membership.user_id if membership else actor_id
    setup.organisation_id = org.id
    db.flush()
    return membership


def recompute_and_maybe_activate(
    db: Session,
    org: Organisation,
    *,
    actor_id: int | None = None,
) -> OrganisationVerificationStatus:
    overall = compute_overall_status(org)
    org.overall_verification_status = overall
    if overall == OrganisationVerificationStatus.VERIFIED:
        activate_verified_organisation(db, org, actor_id=actor_id)
    db.flush()
    return overall


def route_to_manual_review(org: Organisation, *, reason_safe: str | None = None) -> None:
    org.overall_verification_status = OrganisationVerificationStatus.MANUAL_REVIEW
    if reason_safe:
        org.verification_notes_safe = reason_safe[:2000]


def mask_pan(pan: str | None) -> str | None:
    if not pan:
        return None
    value = pan.strip()
    if len(value) <= 4:
        return "****"
    return f"{'*' * (len(value) - 4)}{value[-4:]}"


def invalidate_identity_change(
    org: Organisation,
    *,
    field: str,
) -> None:
    """Mark verification stale when verified identity fields change."""
    field = (field or "").strip().lower()
    if field in {"legal_name", "registration_number"}:
        org.legal_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
        org.legal_verification_reference = None
    elif field == "pan_number":
        org.pan_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
        org.pan_verification_reference = None
    elif field in {"website_domain", "domain"}:
        org.domain_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
    else:
        return
    if org.overall_verification_status == OrganisationVerificationStatus.VERIFIED:
        org.overall_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
        org.overall_verification_method = None
        org.verified_at = None


def verification_status_public(org: Organisation) -> dict:
    settings = get_settings()
    demo = bool(org.demo_verification_simulated) or org.verification_mode == "demo"
    return {
        "organisation_id": org.id,
        "organisation_name": org.name,
        "legal_name": org.legal_name,
        "registration_number": org.registration_number,
        "pan_masked": mask_pan(org.pan_number),
        "website_domain": org.website_domain,
        "legal_verification_status": org.legal_verification_status.value,
        "pan_verification_status": org.pan_verification_status.value,
        "pan_verification_required": bool(settings.pan_verification_required),
        "domain_verification_status": org.domain_verification_status.value,
        "admin_email_verification_status": org.admin_email_verification_status.value,
        "overall_verification_status": org.overall_verification_status.value,
        "overall_verification_method": org.overall_verification_method,
        "legal_verification_method": org.legal_verification_method,
        "verification_mode": org.verification_mode,
        "demo_verification_simulated": demo,
        "demo_banner": "Demo Organisation — Verification Simulated" if demo else None,
        "legal_verification_source": org.legal_verification_source,
        "policy_satisfied": policy_requirements_met(org),
        "organisation_operational_status": org.status.value,
    }
