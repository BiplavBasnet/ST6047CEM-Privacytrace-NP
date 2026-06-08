from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.counterfactual_analysis_schema import (
    CounterfactualAnalysisListResponse,
    CounterfactualAnalysisRead,
    CounterfactualRunRequest,
    CounterfactualRunResponse,
)
from app.services import counterfactual_analysis_service, permission_service

router = APIRouter(tags=["counterfactual-analysis"])


def _error(exc: Exception) -> None:
    if isinstance(
        exc, counterfactual_analysis_service.CounterfactualNotFoundError
    ):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/counterfactual-analysis",
    response_model=CounterfactualRunResponse,
)
def run_counterfactual_analysis(
    incident_id: str,
    body: CounterfactualRunRequest,
    user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_COUNTERFACTUAL_RUN)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        analysis, created = counterfactual_analysis_service.run_analysis(
            db, incident_id, body, actor_id=user.id
        )
        return CounterfactualRunResponse(analysis=analysis, created=created)
    except counterfactual_analysis_service.CounterfactualError as exc:
        _error(exc)


@router.get(
    "/incidents/{incident_id}/counterfactual-analysis",
    response_model=CounterfactualAnalysisListResponse,
)
def list_incident_counterfactual_analyses(
    incident_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_COUNTERFACTUAL_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    items = counterfactual_analysis_service.list_incident_analyses(db, incident_id)
    return CounterfactualAnalysisListResponse(analyses=items, total=len(items))


@router.get(
    "/counterfactual-analysis/{analysis_id}",
    response_model=CounterfactualAnalysisRead,
)
def get_counterfactual_analysis(
    analysis_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_COUNTERFACTUAL_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return counterfactual_analysis_service.get_analysis(db, analysis_id)
    except counterfactual_analysis_service.CounterfactualError as exc:
        _error(exc)


@router.get(
    "/root-causes/{root_cause_id}/counterfactual-analysis",
    response_model=CounterfactualAnalysisListResponse,
)
def list_root_cause_counterfactual_analyses(
    root_cause_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_COUNTERFACTUAL_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    items = counterfactual_analysis_service.list_root_cause_analyses(
        db, root_cause_id
    )
    return CounterfactualAnalysisListResponse(analyses=items, total=len(items))
