from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.breach_decision_schema import (
    BreachDecisionApproveRequest,
    BreachDecisionCreate,
    BreachDecisionDifferenceResponse,
    BreachDecisionFactorRead,
    BreachDecisionListResponse,
    BreachDecisionRead,
    BreachDecisionReviewRequest,
    BreachDecisionSupersedeRequest,
)
from app.services import breach_decision_service, permission_service

router = APIRouter(tags=["breach-decisions"])


def _error(exc: Exception) -> None:
    if isinstance(exc, breach_decision_service.BreachDecisionNotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/breach-decisions",
    response_model=BreachDecisionRead,
)
def create_breach_decision(
    incident_id: str,
    body: BreachDecisionCreate,
    user: Annotated[
        User,
        Depends(
            require_permission(permission_service.PERMISSION_BREACH_DECISION_CREATE)
        ),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.create_decision(
            db, incident_id, body, actor_id=user.id
        )
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)


@router.get(
    "/incidents/{incident_id}/breach-decisions",
    response_model=BreachDecisionListResponse,
)
def list_breach_decisions(
    incident_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_BREACH_DECISION_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    items = breach_decision_service.list_decisions(db, incident_id)
    return BreachDecisionListResponse(decisions=items, total=len(items))


@router.get("/breach-decisions/{decision_id}", response_model=BreachDecisionRead)
def get_breach_decision(
    decision_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_BREACH_DECISION_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.get_decision(db, decision_id)
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)


@router.post(
    "/breach-decisions/{decision_id}/review",
    response_model=BreachDecisionRead,
)
def review_breach_decision(
    decision_id: str,
    body: BreachDecisionReviewRequest,
    user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_BREACH_DECISION_REVIEW)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.review_decision(
            db, decision_id, body, actor_id=user.id
        )
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)


@router.post(
    "/breach-decisions/{decision_id}/approve",
    response_model=BreachDecisionRead,
)
def approve_breach_decision(
    decision_id: str,
    body: BreachDecisionApproveRequest,
    user: Annotated[
        User,
        Depends(
            require_permission(permission_service.PERMISSION_BREACH_DECISION_APPROVE)
        ),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.approve_decision(
            db, decision_id, actor_id=user.id, reason=body.reason
        )
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)


@router.post(
    "/breach-decisions/{decision_id}/supersede",
    response_model=BreachDecisionRead,
)
def supersede_breach_decision(
    decision_id: str,
    body: BreachDecisionSupersedeRequest,
    user: Annotated[
        User,
        Depends(
            require_permission(permission_service.PERMISSION_BREACH_DECISION_APPROVE)
        ),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.supersede_decision(
            db, decision_id, body, actor_id=user.id
        )
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)


@router.get(
    "/breach-decisions/{decision_id}/factors",
    response_model=list[BreachDecisionFactorRead],
)
def list_breach_decision_factors(
    decision_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_BREACH_DECISION_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.get_decision(db, decision_id).factors
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)


@router.get(
    "/breach-decisions/{decision_id}/differences",
    response_model=BreachDecisionDifferenceResponse,
)
def get_breach_decision_differences(
    decision_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_BREACH_DECISION_READ)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return breach_decision_service.get_differences(db, decision_id)
    except breach_decision_service.BreachDecisionError as exc:
        _error(exc)
