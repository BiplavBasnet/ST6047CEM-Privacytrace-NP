from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.schemas.review_schema import (
    ReviewDecisionRead,
    ReviewDraftRead,
    ReviewDraftUpsert,
    ReviewListResponse,
    SubmitReviewRequest,
    SubmitReviewResponse,
)
from app.services import review_service

router = APIRouter(prefix="/incidents", tags=["human-review"])


@router.post("/{incident_id}/review", response_model=SubmitReviewResponse)
def submit_incident_review(
    incident_id: str,
    body: SubmitReviewRequest,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        result = review_service.submit_review(
            db,
            incident_id,
            decision=body.decision,
            reviewer_id=current_user.id,
            comment=body.comment,
            reason=body.reason,
            evidence_checklist=body.evidence_checklist,
            evidence_relied_on=body.evidence_relied_on,
            evidence_limitations=body.evidence_limitations,
            missing_evidence_acknowledged=body.missing_evidence_acknowledged,
        )
    except review_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except review_service.AnalyseRequiredError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except review_service.InvalidDecisionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except review_service.UnsafeReviewCommentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except review_service.ReviewReasonRequiredError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except review_service.ReviewerNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return SubmitReviewResponse(
        review=ReviewDecisionRead.model_validate(result.review),
        incident_status=result.incident_status.value,
        audit_log_id=result.audit_log.id,
    )


@router.get("/{incident_id}/reviews", response_model=ReviewListResponse)
def list_incident_reviews(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW_READ))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        reviews = review_service.list_reviews(db, incident_id)
    except review_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    items = [ReviewDecisionRead.model_validate(r) for r in reviews]
    return ReviewListResponse(
        incident_id=incident_id,
        reviews=items,
        total=len(items),
    )


@router.put("/{incident_id}/review-draft", response_model=ReviewDraftRead)
def save_incident_review_draft(
    incident_id: str,
    body: ReviewDraftUpsert,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return review_service.upsert_review_draft(
            db,
            incident_id,
            reviewer_id=current_user.id,
            selected_decision=body.selected_decision,
            reason=body.reason,
            evidence_checklist=body.evidence_checklist,
            evidence_relied_on=body.evidence_relied_on,
            evidence_limitations=body.evidence_limitations,
            missing_evidence_notes=body.missing_evidence_notes,
            missing_evidence_acknowledged=body.missing_evidence_acknowledged,
        )
    except review_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (review_service.InvalidDecisionError, review_service.UnsafeReviewCommentError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{incident_id}/review-draft", response_model=ReviewDraftRead | None)
def get_incident_review_draft(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        return review_service.get_review_draft(db, incident_id)
    except review_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{incident_id}/review-draft", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident_review_draft(
    incident_id: str,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_REVIEW))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        review_service.delete_review_draft(db, incident_id, reviewer_id=current_user.id)
    except review_service.IncidentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
