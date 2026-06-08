from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.exposure_profile_schema import (
    ExposureCombinationRuleRead,
    ExposureProfileListResponse,
    ExposureProfileRead,
    ExposureProfileReasonRequest,
    ExposureProfileReviewRequest,
)
from app.services import exposure_profile_service, permission_service


router = APIRouter(tags=["exposure-profiles"])


def _restricted_access(db: Session, user: User) -> bool:
    return permission_service.restricted_detection_authorised(db, user)


@router.get("/incidents/{incident_id}/exposure-profiles", response_model=ExposureProfileListResponse)
def list_exposure_profiles(
    incident_id: str,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_EXPOSURE_PROFILE_READ))],
    db: Session = Depends(get_db_session),
):
    authorised = _restricted_access(db, user)
    profiles, restricted_present = exposure_profile_service.list_profiles(db, incident_id, authorised_restricted_access=authorised)
    return ExposureProfileListResponse(
        incident_id=incident_id,
        profiles=profiles,
        total=len(profiles),
        restricted_information_present=restricted_present,
        restricted_message="Restricted compliance exposure is present and requires authorised access." if restricted_present and not authorised else None,
    )


@router.post("/incidents/{incident_id}/exposure-profiles/recalculate", response_model=ExposureProfileListResponse)
def recalculate_exposure_profiles(
    incident_id: str,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_EXPOSURE_PROFILE_RECALCULATE))],
    db: Session = Depends(get_db_session),
):
    try:
        exposure_profile_service.recalculate_profiles(db, incident_id, actor_id=user.id)
        profiles, restricted_present = exposure_profile_service.list_profiles(db, incident_id, authorised_restricted_access=_restricted_access(db, user))
        return ExposureProfileListResponse(incident_id=incident_id, profiles=profiles, total=len(profiles), restricted_information_present=restricted_present, restricted_message="Restricted compliance exposure is present and requires authorised access." if restricted_present and not _restricted_access(db, user) else None)
    except exposure_profile_service.ExposureProfileError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/exposure-profiles/{profile_id}", response_model=ExposureProfileRead)
def get_exposure_profile(
    profile_id: str,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_EXPOSURE_PROFILE_READ))],
    db: Session = Depends(get_db_session),
):
    try:
        return exposure_profile_service.get_profile(db, profile_id, authorised_restricted_access=_restricted_access(db, user))
    except exposure_profile_service.ExposureProfileError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

@router.post("/exposure-profiles/{profile_id}/review", response_model=ExposureProfileRead)
def review_exposure_profile(
    profile_id: str,
    body: ExposureProfileReviewRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_EXPOSURE_PROFILE_REVIEW))],
    db: Session = Depends(get_db_session),
):
    try:
        return exposure_profile_service.review_profile(db, profile_id, actor_id=user.id, decision=body.decision, reason=body.reason)
    except exposure_profile_service.ExposureProfileError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/exposure-profiles/{profile_id}/reject", response_model=ExposureProfileRead)
def reject_exposure_profile(
    profile_id: str,
    body: ExposureProfileReasonRequest,
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_EXPOSURE_PROFILE_REVIEW))],
    db: Session = Depends(get_db_session),
):
    try:
        return exposure_profile_service.review_profile(db, profile_id, actor_id=user.id, decision="rejected", reason=body.reason)
    except exposure_profile_service.ExposureProfileError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

@router.get("/taxonomy/exposure-combination-rules", response_model=list[ExposureCombinationRuleRead])
@router.get("/exposure-combination-rules", response_model=list[ExposureCombinationRuleRead])
def list_exposure_combination_rules(
    user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_TAXONOMY_READ))],
    db: Session = Depends(get_db_session),
):
    rules = exposure_profile_service.combination_rules()
    if not _restricted_access(db, user):
        rules = [rule for rule in rules if not rule["internal_only"]]
    return rules

