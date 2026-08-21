"""Organisation, membership, invitation, setup, and verification state.

PrivacyTrace-NP is one organisation per deployment. These tables keep
ownership explicit without implementing shared-database multi-tenancy.
"""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import (
    DomainChallengeStatus,
    InvitationStatus,
    ManualReviewStatus,
    MembershipStatus,
    OrganisationStatus,
    OrganisationVerificationStatus,
    UserRole,
)

if TYPE_CHECKING:
    from app.models.user import User


class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    status: Mapped[OrganisationStatus] = mapped_column(
        Enum(OrganisationStatus, name="organisation_status", native_enum=False),
        nullable=False,
        default=OrganisationStatus.ACTIVE,
        server_default=OrganisationStatus.ACTIVE.value,
    )
    # one row per deployment; unique slot blocks a second org.
    deployment_slot: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, default=1, server_default="1")
    approved_email_domains: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    legal_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registration_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pan_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    registered_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    website_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    legal_verification_status: Mapped[OrganisationVerificationStatus] = mapped_column(
        Enum(OrganisationVerificationStatus, name="organisation_verification_status", native_enum=False),
        nullable=False,
        default=OrganisationVerificationStatus.UNVERIFIED,
        server_default=OrganisationVerificationStatus.UNVERIFIED.value,
    )
    pan_verification_status: Mapped[OrganisationVerificationStatus] = mapped_column(
        Enum(OrganisationVerificationStatus, name="organisation_verification_status", native_enum=False),
        nullable=False,
        default=OrganisationVerificationStatus.UNVERIFIED,
        server_default=OrganisationVerificationStatus.UNVERIFIED.value,
    )
    domain_verification_status: Mapped[OrganisationVerificationStatus] = mapped_column(
        Enum(OrganisationVerificationStatus, name="organisation_verification_status", native_enum=False),
        nullable=False,
        default=OrganisationVerificationStatus.UNVERIFIED,
        server_default=OrganisationVerificationStatus.UNVERIFIED.value,
    )
    admin_email_verification_status: Mapped[OrganisationVerificationStatus] = mapped_column(
        Enum(OrganisationVerificationStatus, name="organisation_verification_status", native_enum=False),
        nullable=False,
        default=OrganisationVerificationStatus.UNVERIFIED,
        server_default=OrganisationVerificationStatus.UNVERIFIED.value,
    )
    overall_verification_status: Mapped[OrganisationVerificationStatus] = mapped_column(
        Enum(OrganisationVerificationStatus, name="organisation_verification_status", native_enum=False),
        nullable=False,
        default=OrganisationVerificationStatus.UNVERIFIED,
        server_default=OrganisationVerificationStatus.UNVERIFIED.value,
        index=True,
    )
    overall_verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    legal_verification_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    legal_verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    legal_verification_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pan_verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pan_verification_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verification_notes_safe: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="manual", server_default="manual")
    demo_verification_simulated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    allow_external_admin_email: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    memberships: Mapped[list["OrganisationMembership"]] = relationship(
        "OrganisationMembership", back_populates="organisation"
    )


class OrganisationMembership(Base):
    __tablename__ = "organisation_memberships"
    __table_args__ = (UniqueConstraint("organisation_id", "user_id", name="uq_org_membership_user"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organisation_id: Mapped[int] = mapped_column(
        ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=False),
        nullable=False,
    )
    status: Mapped[MembershipStatus] = mapped_column(
        Enum(MembershipStatus, name="membership_status", native_enum=False),
        nullable=False,
        default=MembershipStatus.PENDING,
        server_default=MembershipStatus.PENDING.value,
        index=True,
    )
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    organisation: Mapped["Organisation"] = relationship("Organisation", back_populates="memberships")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    approver: Mapped["User | None"] = relationship("User", foreign_keys=[approved_by])


class OrganisationInvitation(Base):
    __tablename__ = "organisation_invitations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organisation_id: Mapped[int] = mapped_column(
        ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=False),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    invited_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[InvitationStatus] = mapped_column(
        Enum(InvitationStatus, name="invitation_status", native_enum=False),
        nullable=False,
        default=InvitationStatus.PENDING,
        server_default=InvitationStatus.PENDING.value,
        index=True,
    )

    organisation: Mapped["Organisation"] = relationship("Organisation")
    inviter: Mapped["User"] = relationship("User", foreign_keys=[invited_by])


class DeploymentSetup(Base):
    __tablename__ = "deployment_setup"

    id: Mapped[int] = mapped_column(primary_key=True)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    organisation_id: Mapped[int | None] = mapped_column(
        ForeignKey("organisations.id", ondelete="SET NULL"), nullable=True
    )
    bootstrap_consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    bootstrap_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class OrganisationDomainChallenge(Base):
    __tablename__ = "organisation_domain_challenges"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organisation_id: Mapped[int] = mapped_column(
        ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[DomainChallengeStatus] = mapped_column(
        Enum(DomainChallengeStatus, name="domain_challenge_status", native_enum=False),
        nullable=False,
        default=DomainChallengeStatus.PENDING,
        server_default=DomainChallengeStatus.PENDING.value,
        index=True,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")


class OrganisationEmailVerification(Base):
    __tablename__ = "organisation_email_verifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organisation_id: Mapped[int] = mapped_column(
        ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")


class OrganisationManualReview(Base):
    __tablename__ = "organisation_manual_reviews"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    organisation_id: Mapped[int] = mapped_column(
        ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ManualReviewStatus] = mapped_column(
        Enum(ManualReviewStatus, name="manual_review_status", native_enum=False),
        nullable=False,
        default=ManualReviewStatus.OPEN,
        server_default=ManualReviewStatus.OPEN.value,
        index=True,
    )
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewer_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decision_notes_safe: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    official_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reference_safe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
