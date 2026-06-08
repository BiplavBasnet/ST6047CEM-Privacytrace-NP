"""Authentication dependencies scoped to Universal Integration Gateway ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.services import auth_service, integration_token_service, organisation_access_service as org_access, permission_service

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class IntegrationPrincipal:
    actor_id: int | None
    actor_email: str | None
    actor_role: str
    source_name: str | None
    auth_type: str
    organisation_id: int | None = None


def require_integration_ingest_principal(
    db: Session = Depends(get_db_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> IntegrationPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Integration authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    if token.startswith(integration_token_service.TOKEN_PREFIX):
        try:
            record = integration_token_service.authenticate_token(db, token)
        except integration_token_service.InvalidIntegrationTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if record.organisation_id:
            from app.models.enums import OrganisationStatus, OrganisationVerificationStatus
            from app.models.organisation import Organisation

            org = db.get(Organisation, record.organisation_id)
            if org is None or org.status != OrganisationStatus.ACTIVE:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="This organisation is suspended.",
                )
            if org.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Organisation verification is incomplete.",
                )
        return IntegrationPrincipal(
            actor_id=record.created_by_user_id,
            actor_email=None,
            actor_role="integration_token",
            source_name=record.source_name,
            auth_type="integration_token",
            organisation_id=record.organisation_id,
        )

    try:
        user = auth_service.get_user_from_token(db, token)
    except auth_service.InactiveUserError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except auth_service.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if not permission_service.role_has_permission(
        user.role,
        permission_service.PERMISSION_INTEGRATION_INGEST,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: integration:ingest",
        )
    try:
        membership = org_access.require_active_membership(db, user)
    except org_access.OrganisationAccessError as extra:
        raise HTTPException(status_code=extra.status_code, detail=str(extra)) from extra
    return IntegrationPrincipal(
        actor_id=user.id,
        actor_email=user.email,
        actor_role=membership.role.value,
        source_name=None,
        auth_type="user_jwt",
        organisation_id=membership.organisation_id,
    )
