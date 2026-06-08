"""FastAPI dependencies for JWT authentication and RBAC."""

from __future__ import annotations

from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.models.user import User
from app.services import audit_service, auth_service, organisation_access_service as org_access, permission_service

_bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    db: Session = Depends(get_db_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return auth_service.get_user_from_token(db, credentials.credentials)
    except auth_service.InactiveUserError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except auth_service.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_permission(permission: str) -> Callable:
    def _checker(
        current_user: Annotated[User, Depends(get_current_user)],
        db: Session = Depends(get_db_session),
    ) -> User:
        try:
            membership = org_access.require_active_membership(db, current_user)
        except org_access.OrganisationAccessError as extra:
            log_permission_denied(db, user=current_user, permission=permission)
            db.commit()
            raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
        if not permission_service.role_has_permission(membership.role, permission):
            log_permission_denied(db, user=current_user, permission=permission)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )
        return current_user

    return _checker


def get_current_membership(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db_session),
):
    try:
        return org_access.require_active_membership(db, current_user)
    except org_access.OrganisationAccessError as extra:
        raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra


def require_organisation_role(*roles: str) -> Callable:
    allowed = {item.lower() for item in roles}

    def _checker(
        current_user: Annotated[User, Depends(get_current_user)],
        db: Session = Depends(get_db_session),
    ) -> User:
        try:
            membership = org_access.require_active_membership(db, current_user)
        except org_access.OrganisationAccessError as extra:
            raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
        if membership.role.value not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        return current_user

    return _checker



def log_permission_denied(
    db: Session,
    *,
    user: User,
    permission: str,
    target_type: str | None = None,
    target_id: str | None = None,
) -> None:
    audit_service.log_action(
        db,
        action=audit_service.ACTION_PERMISSION_DENIED,
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role.value,
        target_type=target_type,
        target_id=target_id,
        details={"permission": permission},
    )
