from typing import Annotated

from fastapi import APIRouter, Depends

from app.dependencies.auth_dependencies import get_current_user, require_permission
from app.models.user import User
from app.schemas.security_schema import (
    SecurityKeyStatusResponse,
    SecurityProfileResponse,
    SecuritySelfCheckResponse,
)
from app.services import permission_service, security_profile_service

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/profile", response_model=SecurityProfileResponse)
def security_profile(
    _user: Annotated[User, Depends(get_current_user)],
):
    return SecurityProfileResponse(**security_profile_service.get_security_profile())


@router.get("/self-check", response_model=SecuritySelfCheckResponse)
def security_self_check(
    _user: Annotated[User, Depends(get_current_user)],
):
    return SecuritySelfCheckResponse(**security_profile_service.run_self_check())


@router.get("/key-status", response_model=SecurityKeyStatusResponse)
def security_key_status(
    _admin: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))
    ],
):
    return SecurityKeyStatusResponse(**security_profile_service.get_key_status())
