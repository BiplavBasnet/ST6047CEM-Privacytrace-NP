from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import InvitationStatus, MembershipStatus, OrganisationStatus, UserRole
from app.schemas.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_strength,
)


class SetupStatusResponse(BaseModel):
    required: bool
    completed: bool
    verification_pending: bool = False
    bootstrap_required: bool = False
    registration_open: bool = False


class SetupOrganisationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organisation_name: str = Field(min_length=1, max_length=255)
    administrator_full_name: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    confirm_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    bootstrap_token: str = Field(min_length=8, max_length=512)
    legal_name: str | None = Field(default=None, max_length=255)
    registration_number: str | None = Field(default=None, max_length=64)
    pan_number: str | None = Field(default=None, max_length=64)
    registered_address: str | None = Field(default=None, max_length=2000)
    website_domain: str | None = Field(default=None, max_length=255)

    @field_validator("organisation_name", "administrator_full_name")
    @classmethod
    def strip_required(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("This field is required")
        return stripped

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        email = value.strip().lower()
        if "@" not in email or "." not in email.split("@")[-1] or " " in email:
            raise ValueError("Invalid email format")
        return email

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        return validate_password_strength(value) or value

    @model_validator(mode="after")
    def passwords_match(self) -> "SetupOrganisationRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class MembershipRead(BaseModel):
    organisation_id: int
    organisation_name: str | None = None
    organisation_status: OrganisationStatus | str | None = None
    overall_verification_status: str | None = None
    demo_verification_simulated: bool = False
    role: UserRole
    status: MembershipStatus | str


class SetupOrganisationResponse(BaseModel):
    organisation_id: int
    organisation_name: str
    organisation_slug: str
    administrator_id: int
    administrator_email: str
    role: UserRole
    overall_verification_status: str
    membership_status: str
    message: str = (
        "Company registered. Complete legal, domain, and email verification before "
        "Organisation Admin access is activated."
    )


class VerificationStatusResponse(BaseModel):
    organisation_id: int
    organisation_name: str
    legal_name: str | None = None
    registration_number: str | None = None
    pan_masked: str | None = None
    website_domain: str | None = None
    legal_verification_status: str
    pan_verification_status: str
    pan_verification_required: bool
    domain_verification_status: str
    admin_email_verification_status: str
    overall_verification_status: str
    overall_verification_method: str | None = None
    legal_verification_method: str | None = None
    verification_mode: str
    demo_verification_simulated: bool
    demo_banner: str | None = None
    legal_verification_source: str | None = None
    policy_satisfied: bool
    setup_completed: bool = False
    organisation_operational_status: str | None = None


class OrganisationSuspendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=500)


class PlatformAdminRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: int
    reason: str = Field(min_length=3, max_length=500)

class LegalVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    legal_name: str | None = Field(default=None, max_length=255)
    registration_number: str | None = Field(default=None, max_length=64)
    registry_name: str | None = Field(default=None, max_length=255)
    match_status: str | None = Field(default=None, max_length=64)
    reference_safe: str | None = Field(default=None, max_length=255)


class PanVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pan: str = Field(min_length=1, max_length=64)
    match_status: str | None = Field(default=None, max_length=64)
    reference_safe: str | None = Field(default=None, max_length=255)


class DomainChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=3, max_length=255)


class DomainVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    txt_record: str | None = Field(default=None, max_length=512)


class DomainChallengeResponse(BaseModel):
    domain: str
    txt_record: str
    expires_at: datetime
    status: str


class EmailTokenIssueResponse(BaseModel):
    email: str
    expires_at: datetime
    verify_path: str | None = None
    verify_token: str | None = None
    delivery: str = "none"
    demo_simulated: bool = False


class EmailTokenConsumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=8, max_length=256)


class ManualReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=255)


class ManualReviewDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(min_length=3, max_length=32)
    notes_safe: str = Field(min_length=3, max_length=2000)


class InvitationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=5, max_length=255)
    role: UserRole
    organisation_id: int | None = None

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class InvitationCreatedResponse(BaseModel):
    id: int
    email: str
    role: UserRole
    status: InvitationStatus
    expires_at: datetime
    invite_token: str | None = None
    invite_path: str | None = None
    domain_warning: str | None = None
    delivery: str = "api"
    demo_simulated: bool = False


class InvitationPreviewResponse(BaseModel):
    email: str
    role: UserRole
    organisation_name: str
    expires_at: datetime


class InvitationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: UserRole
    status: InvitationStatus
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None


class RoleChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole
    reason: str | None = Field(default=None, max_length=500)
    organisation_id: int | None = None


class MembershipStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: MembershipStatus
    organisation_id: int | None = None


class AssignMembershipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: UserRole
    organisation_id: int | None = None
