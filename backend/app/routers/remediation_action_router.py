from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.remediation_action_schema import (
    RemediationActionCreate,
    RemediationActionListResponse,
    RemediationActionResponse,
    RemediationActionUpdate,
)
from app.services import permission_service, remediation_action_service

router = APIRouter(tags=["remediation-actions"])


def _handle_error(exc: Exception) -> None:
    if isinstance(
        exc,
        (
            remediation_action_service.IncidentNotFoundError,
            remediation_action_service.RemediationActionNotFoundError,
        ),
    ):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/remediation-actions",
    response_model=RemediationActionResponse,
)
def create_incident_remediation_action(
    incident_id: str,
    body: RemediationActionCreate,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return remediation_action_service.create_remediation_action(
            db,
            incident_id,
            created_by=current_user.id,
            **body.model_dump(),
        )
    except remediation_action_service.RemediationActionError as exc:
        _handle_error(exc)


@router.get(
    "/incidents/{incident_id}/remediation-actions",
    response_model=RemediationActionListResponse,
)
def list_incident_remediation_actions(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        actions = remediation_action_service.list_remediation_actions(db, incident_id)
    except remediation_action_service.RemediationActionError as exc:
        _handle_error(exc)
    return RemediationActionListResponse(
        incident_id=incident_id,
        remediation_actions=[RemediationActionResponse.model_validate(item) for item in actions],
        total=len(actions),
    )


@router.get(
    "/remediation-actions/{remediation_action_id}",
    response_model=RemediationActionResponse,
)
def get_remediation_action(
    remediation_action_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return remediation_action_service.get_remediation_action(db, remediation_action_id)
    except remediation_action_service.RemediationActionError as exc:
        _handle_error(exc)


@router.patch(
    "/remediation-actions/{remediation_action_id}",
    response_model=RemediationActionResponse,
)
def patch_remediation_action(
    remediation_action_id: str,
    body: RemediationActionUpdate,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return remediation_action_service.update_remediation_action(
            db,
            remediation_action_id,
            updated_by=current_user.id,
            changes=body.model_dump(exclude_unset=True),
        )
    except remediation_action_service.RemediationActionError as exc:
        _handle_error(exc)

