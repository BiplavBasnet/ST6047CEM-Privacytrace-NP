from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.remediation_lifecycle_schema import (
    ControlledRetestCreate,
    ControlledRetestRead,
    ImplementationCreate,
    ImplementationRead,
    RemediationLifecycleStatus,
)
from app.schemas.ai_remediation_schema import SandboxTestRequest
from app.services import (
    permission_service,
    remediation_lifecycle_service,
    sandbox_test_execution_service,
)

router = APIRouter(prefix="/incidents", tags=["remediation-lifecycle"])


@router.post("/{incident_id}/remediation-tests/run")
def run_remediation_test(
    incident_id: str,
    body: SandboxTestRequest,
    user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_FIX_VERIFY))
    ],
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        return sandbox_test_execution_service.run_profile(
            body.profile,
            db=db,
            incident_id=incident_id,
            remediation_action_id=body.remediation_action_id,
            implementation_id=body.implementation_id,
            patch_proposal_id=body.patch_proposal_id,
            executed_by=user.email,
            actor_id=user.id,
        )
    except (
        sandbox_test_execution_service.SandboxTestError,
        remediation_lifecycle_service.RemediationLifecycleError,
    ) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{incident_id}/implementations", response_model=ImplementationRead)
def create_implementation(
    incident_id: str,
    body: ImplementationCreate,
    user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_FIX_VERIFY))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        row = remediation_lifecycle_service.record_implementation(
            db,
            actor_id=user.id,
            expected_incident_id=incident_id,
            **body.model_dump(),
        )
        return row
    except remediation_lifecycle_service.RemediationLifecycleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{incident_id}/controlled-retests", response_model=ControlledRetestRead)
def create_controlled_retest(
    incident_id: str,
    body: ControlledRetestCreate,
    user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_FIX_VERIFY))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        row = remediation_lifecycle_service.record_controlled_retest(
            db,
            actor_id=user.id,
            expected_incident_id=incident_id,
            **body.model_dump(),
        )
        return row
    except remediation_lifecycle_service.RemediationLifecycleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{incident_id}/remediation-lifecycle", response_model=RemediationLifecycleStatus)
def get_remediation_lifecycle(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_FIX_READ))
    ],
    db: Session = Depends(get_db_session),
):
    facts = remediation_lifecycle_service.current_lifecycle_records(db, incident_id)
    return RemediationLifecycleStatus(incident_id=incident_id, **facts)
