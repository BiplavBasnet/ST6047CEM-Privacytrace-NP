from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import UserRole
from app.schemas.organisation_schema import MembershipRead
from app.schemas.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_strength,
)


class LoginRequest(BaseModel):
    # Demo accounts use *.local addresses; avoid strict EmailStr reserved-domain rejection.
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class AuthUserRead(BaseModel):
    id: int
    name: str
    email: str
    role: UserRole
    membership: MembershipRead | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUserRead


class LogoutResponse(BaseModel):
    message: str = "Logged out successfully. Remove the token on the client."


class RegisterRequest(BaseModel):
    """Public self-registration. Role/permission fields are rejected via extra=forbid."""

    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    confirm_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    invite_token: str | None = Field(default=None, max_length=256)

    @field_validator("full_name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Full name is required")
        return stripped

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        email = value.strip()
        if "@" not in email or "." not in email.split("@")[-1]:
            raise ValueError("Invalid email format")
        local, _, domain = email.partition("@")
        if not local or not domain or " " in email:
            raise ValueError("Invalid email format")
        return email

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        return validate_password_strength(value) or value

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class RegisterResponse(BaseModel):
    id: int
    name: str
    email: str
    role: UserRole
    message: str = "Account created. Sign in with your email and password."


class RegistrationStatusResponse(BaseModel):
    enabled: bool
    email_verification_required: bool
    default_role: str
    invite_only: bool = False


class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=5, max_length=255)


class PasswordResetConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=8, max_length=256)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    confirm_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        return validate_password_strength(value) or value

    @model_validator(mode="after")
    def passwords_match(self) -> "PasswordResetConfirmRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class PasswordResetRequestResponse(BaseModel):
    message: str = "If an account exists for that email, a reset link was issued."
    demo_reset_token: str | None = None
    demo_simulated: bool = False
