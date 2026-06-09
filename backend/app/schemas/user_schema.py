from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import UserRole
from app.schemas.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_strength,
)


class UserCreate(BaseModel):
    name: str
    email: str = Field(min_length=5, max_length=255)
    role: UserRole
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        return validate_password_strength(value) or value

    @field_validator("role")
    @classmethod
    def reject_platform_admin(cls, value: UserRole) -> UserRole:
        if value == UserRole.PLATFORM_ADMIN:
            raise ValueError("Platform administrator cannot be assigned this way.")
        return value


class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = Field(default=None, min_length=5, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(
        default=None, min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH
    )

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str | None) -> str | None:
        return validate_password_strength(value)

    @field_validator("role")
    @classmethod
    def reject_platform_admin(cls, value: UserRole | None) -> UserRole | None:
        if value == UserRole.PLATFORM_ADMIN:
            raise ValueError("Platform administrator cannot be assigned this way.")
        return value


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None
    updated_at: datetime | None = None
    membership_status: str | None = None
    membership_role: UserRole | None = None
    organisation_id: int | None = None


class UserListResponse(BaseModel):
    users: list[UserRead]
    total: int
