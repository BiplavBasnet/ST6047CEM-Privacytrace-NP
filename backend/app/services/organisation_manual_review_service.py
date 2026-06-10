"""Minimal manual organisation verification fallback."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import ManualReviewStatus, OrganisationVerificationStatus, UserRole
from app.models.organisation import Organisation, OrganisationManualReview, OrganisationMembership
from app.models.user import User
from app.services import organisation_verification_policy_service as policy


class ManualReviewError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def request_manual_review(
    db: Session,
    org: Organisation,
    *,
    reason: str,
    requested_by: int | None,
) -> OrganisationManualReview:
    reason_clean = (reason or "").strip()
    if not reason_clean:
        raise ManualReviewError("Manual review reason is required")
    open_row = db.scalar(
        select(OrganisationManualReview)
        .where(
            OrganisationManualReview.organisation_id == org.id,
            OrganisationManualReview.status == ManualReviewStatus.OPEN,
        )
        .limit(1)
    )
    if open_row is not None:
        open_row.reason = reason_clean[:255]
        policy.route_to_manual_review(org, reason_safe=reason_clean)
        db.flush()
        return open_row
    row = OrganisationManualReview(
        organisation_id=org.id,
        reason=reason_clean[:255],
        status=ManualReviewStatus.OPEN,
        requested_by=requested_by,
    )
    db.add(row)
    policy.route_to_manual_review(org, reason_safe=reason_clean)
    db.flush()
    return row


def decide_manual_review(
    db: Session,
    review_id: int,
    *,
    reviewer: User,
    decision: str,
    notes_safe: str,
) -> OrganisationManualReview:
    if reviewer.role != UserRole.PLATFORM_ADMIN:
        raise ManualReviewError("Only a platform administrator may decide manual reviews", status_code=403)
    notes = (notes_safe or "").strip()
    if not notes:
        raise ManualReviewError("Decision reason is required")
    decision_norm = (decision or "").strip().lower()
    if decision_norm not in {"approve", "reject", "more_info"}:
        raise ManualReviewError("Decision must be approve, reject, or more_info")

    row = db.get(OrganisationManualReview, review_id)
    if row is None or row.status != ManualReviewStatus.OPEN:
        raise ManualReviewError("Open manual review not found", status_code=404)
    org = db.get(Organisation, row.organisation_id)
    if org is None:
        raise ManualReviewError("Organisation missing", status_code=404)

    now = datetime.now(UTC)
    row.reviewer_id = reviewer.id
    row.decision_notes_safe = notes[:2000]
    row.decided_at = now

    if decision_norm == "approve":
        row.status = ManualReviewStatus.APPROVED
        row.verification_method = "MANUAL_OPERATOR"
        row.official_source = "OFFICIAL_REFERENCE_MANUAL"
        row.reference_safe = (org.legal_verification_reference or f"manual-review-{row.id}")[:255]
        org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
        org.legal_verification_method = "MANUAL_OPERATOR"
        if org.legal_verification_source is None:
            org.legal_verification_source = "OFFICIAL_REFERENCE_MANUAL"
        org.legal_verification_reference = org.legal_verification_reference or f"manual-review-{row.id}"
        org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
        org.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
        org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
        org.allow_external_admin_email = True
        org.overall_verification_method = "MANUAL_OPERATOR"
        membership = db.scalar(
            select(OrganisationMembership)
            .where(
                OrganisationMembership.organisation_id == org.id,
                OrganisationMembership.role.in_((UserRole.ORGANISATION_ADMIN, UserRole.ADMIN)),
            )
            .order_by(OrganisationMembership.id.asc())
            .limit(1)
        )
        if membership is not None:
            user = db.get(User, membership.user_id)
            if user is not None:
                user.admin_email_verified = True
        org.overall_verification_status = OrganisationVerificationStatus.VERIFIED
        policy.activate_verified_organisation(
            db,
            org,
            actor_id=reviewer.id,
            notes_safe=f"Manually verified: {notes}"[:2000],
        )
    elif decision_norm == "reject":
        row.status = ManualReviewStatus.REJECTED
        org.overall_verification_status = OrganisationVerificationStatus.REJECTED
        org.verification_notes_safe = notes[:2000]
    else:
        row.status = ManualReviewStatus.MORE_INFO
        org.overall_verification_status = OrganisationVerificationStatus.MANUAL_REVIEW
        org.verification_notes_safe = notes[:2000]
    db.flush()
    return row
