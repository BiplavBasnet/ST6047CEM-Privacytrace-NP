"""AI Remediation Assistant endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.models.remediation_diagnosis import RemediationDiagnosis
from app.schemas.ai_remediation_schema import (
    AIRemediationAcceptRequest,
    AIRemediationDecisionResponse,
    AIRemediationEditRequest,
    AIRemediationRejectRequest,
    AIRemediationStatusResponse,
    AIRemediationSuggestResponse,
    AIRemediationSuggestionListResponse,
    AIRemediationSuggestionRead,
    ControlledPatchRequest,
    DiagnosisReviewRequest,
    DiagnosisReviewResponse,
    SandboxTestRequest,
)
from app.schemas.problem_specific_remediation_schema import AIProblemSpecificRemediationResponse, CurrentRemediationDiagnosisRead
from app.services import (
    ai_remediation_diagnosis_service,
    ai_remediation_service,
    controlled_patch_service,
    permission_service,
    remediation_action_service,
    sandbox_test_execution_service,
    verified_outcome_learning_service,
)
from app.services.patch_safety_service import PatchSafetyError
from app.services.remediation_ai_safety_service import RemediationAISafetyError

router = APIRouter(prefix="/ai-remediation", tags=["ai-remediation"])


def _actor(user: User) -> dict:
    return {"actor_id": user.id, "actor_email": user.email, "actor_role": user.role.value}


@router.get("/status", response_model=AIRemediationStatusResponse)
def get_ai_remediation_status(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_READ))],
) -> AIRemediationStatusResponse:
    return ai_remediation_service.get_status()


@router.post("/incidents/{incident_id}/suggest", response_model=AIRemediationSuggestResponse)
def suggest_ai_remediation(
    incident_id: str,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_GENERATE))],
    db: Session = Depends(get_db_session),
) -> AIRemediationSuggestResponse:
    try:
        suggestion = ai_remediation_service.generate_suggestion(db, incident_id, **_actor(current_user))
    except ai_remediation_service.AIIncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ai_remediation_service.AIAssistantDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except ai_remediation_service.AIProviderUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except ai_remediation_service.AISafetyBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return AIRemediationSuggestResponse(
        suggestion=suggestion,
        message="AI-generated remediation suggestion created. Human review and fix verification are required.",
    )


@router.get("/incidents/{incident_id}/suggestions", response_model=AIRemediationSuggestionListResponse)
def list_ai_remediation_suggestions(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_READ))],
    db: Session = Depends(get_db_session),
) -> AIRemediationSuggestionListResponse:
    try:
        return ai_remediation_service.list_suggestions(db, incident_id)
    except ai_remediation_service.AIIncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/suggestions/{suggestion_id}", response_model=AIRemediationSuggestionRead)
def get_ai_remediation_suggestion(
    suggestion_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_READ))],
    db: Session = Depends(get_db_session),
) -> AIRemediationSuggestionRead:
    try:
        return ai_remediation_service.get_suggestion(db, suggestion_id)
    except ai_remediation_service.AISuggestionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/suggestions/{suggestion_id}/accept", response_model=AIRemediationDecisionResponse)
def accept_ai_remediation_suggestion(
    suggestion_id: str,
    body: AIRemediationAcceptRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> AIRemediationDecisionResponse:
    try:
        return ai_remediation_service.accept_suggestion(
            db,
            suggestion_id,
            reviewer_notes=body.reviewer_notes,
            create_remediation_action=body.create_remediation_action,
            **_actor(current_user),
        )
    except ai_remediation_service.AISuggestionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (ai_remediation_service.AISafetyBlockedError, ai_remediation_service.AISuggestionStateError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/suggestions/{suggestion_id}/edit", response_model=AIRemediationDecisionResponse)
def edit_ai_remediation_suggestion(
    suggestion_id: str,
    body: AIRemediationEditRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> AIRemediationDecisionResponse:
    try:
        return ai_remediation_service.edit_suggestion(
            db,
            suggestion_id,
            edited_remediation_actions=body.edited_remediation_actions,
            reviewer_notes=body.reviewer_notes,
            **_actor(current_user),
        )
    except ai_remediation_service.AISuggestionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ai_remediation_service.AISafetyBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/suggestions/{suggestion_id}/reject", response_model=AIRemediationDecisionResponse)
def reject_ai_remediation_suggestion(
    suggestion_id: str,
    body: AIRemediationRejectRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> AIRemediationDecisionResponse:
    try:
        return ai_remediation_service.reject_suggestion(
            db,
            suggestion_id,
            reason=body.reason,
            **_actor(current_user),
        )
    except ai_remediation_service.AISuggestionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ai_remediation_service.AISafetyBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/diagnose",
    response_model=AIProblemSpecificRemediationResponse,
)
def diagnose_problem_specific_remediation(
    incident_id: str,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_GENERATE))],
    db: Session = Depends(get_db_session),
) -> AIProblemSpecificRemediationResponse:
    try:
        _row, response = ai_remediation_diagnosis_service.generate_problem_specific_remediation(
            db, incident_id, **_actor(current_user)
        )
        return response
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ai_remediation_diagnosis_service.DiagnosisGateError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RemediationAISafetyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/incidents/{incident_id}/diagnosis/current", response_model=CurrentRemediationDiagnosisRead)
def read_current_problem_specific_diagnosis(
    incident_id: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_READ))],
    db: Session = Depends(get_db_session),
) -> RemediationDiagnosis:
    row = ai_remediation_diagnosis_service.get_current_diagnosis(db, incident_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Current diagnosis not found.")
    return row


@router.post("/diagnoses/{diagnosis_id}/review", response_model=DiagnosisReviewResponse)
def review_problem_specific_diagnosis(
    diagnosis_id: str,
    body: DiagnosisReviewRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> DiagnosisReviewResponse:
    try:
        row = ai_remediation_diagnosis_service.review_diagnosis(
            db,
            diagnosis_id,
            decision=body.decision,
            notes=body.notes,
            edited_primary=body.edited_primary,
            **_actor(current_user),
        )
    except ai_remediation_diagnosis_service.DiagnosisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (
        ai_remediation_diagnosis_service.DiagnosisStateError,
        ai_remediation_diagnosis_service.DiagnosisGateError,
    ) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    # The service owns diagnosis-to-action conversion. The legacy request flag
    # remains accepted, but cannot create a second unbound action.
    canonical_action = ai_remediation_diagnosis_service.get_action_for_diagnosis(
        db, row.diagnosis_id
    )
    remediation_action_id = (
        canonical_action.remediation_action_id if canonical_action is not None else None
    )

    return DiagnosisReviewResponse(
        diagnosis_id=row.diagnosis_id,
        status=row.status,
        reviewer_decision=row.reviewer_decision,
        remediation_action_id=remediation_action_id,
        message=(
            "Human remediation review recorded. Implementation remains gated; "
            "rejected or more-evidence states do not unlock controlled patch execution."
        ),
    )


@router.post("/patches/draft")
def create_controlled_patch_draft(
    body: ControlledPatchRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        diagnosis = controlled_patch_service.require_accepted_diagnosis(db, body.diagnosis_id)
        return controlled_patch_service.generate_draft_patch(db, diagnosis, **_actor(current_user))
    except (
        ai_remediation_diagnosis_service.DiagnosisNotFoundError,
        ai_remediation_diagnosis_service.DiagnosisGateError,
        ai_remediation_diagnosis_service.DiagnosisStateError,
        controlled_patch_service.ControlledPatchError,
        PatchSafetyError,
    ) as exc:
        code = (
            status.HTTP_404_NOT_FOUND
            if "not found" in str(exc).lower()
            else status.HTTP_422_UNPROCESSABLE_ENTITY
        )
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.get("/sandbox-tests/profiles")
def list_sandbox_test_profiles(
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_READ))],
) -> dict:
    return {"profiles": sandbox_test_execution_service.list_profiles()}


@router.post("/sandbox-tests/run")
def run_sandbox_test_profile(
    body: SandboxTestRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        return sandbox_test_execution_service.run_profile(
            body.profile,
            db=db,
            remediation_action_id=body.remediation_action_id,
            implementation_id=body.implementation_id,
            patch_proposal_id=body.patch_proposal_id,
            executed_by=current_user.email,
            actor_id=current_user.id,
        )
    except sandbox_test_execution_service.SandboxTestError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/learning/playbook/{remediation_type}")
def get_playbook_learning_hint(
    remediation_type: str,
    _user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_READ))],
    db: Session = Depends(get_db_session),
) -> dict:
    return verified_outcome_learning_service.playbook_ranking_hint(db, remediation_type)


@router.post("/patches/{patch_proposal_id}/approve-sandbox")
def approve_patch_for_sandbox(
    patch_proposal_id: str,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        row = controlled_patch_service.approve_patch_for_sandbox(
            db, patch_proposal_id, **_actor(current_user)
        )
        return {
            "patch_proposal_id": row.patch_proposal_id,
            "status": row.status,
            "human_approval_status": row.human_approval_status,
            "message": "Human approved patch for sandbox testing only. Production unmodified.",
        }
    except controlled_patch_service.ControlledPatchError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/patches/{patch_proposal_id}/apply-sandbox")
def apply_patch_to_sandbox(
    patch_proposal_id: str,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        row = controlled_patch_service.apply_patch_to_sandbox(
            db, patch_proposal_id, **_actor(current_user)
        )
        return {
            "patch_proposal_id": row.patch_proposal_id,
            "status": row.status,
            "temporary_workspace": row.temporary_workspace,
            "applied_at": row.applied_at.isoformat() if row.applied_at else None,
            "applied_to_production": False,
            "message": "Patch applied to controlled sandbox workspace only.",
        }
    except controlled_patch_service.ControlledPatchError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/patches/{patch_proposal_id}/rollback-sandbox")
def rollback_sandbox_patch(
    patch_proposal_id: str,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_AI_REMEDIATION_REVIEW))],
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        row = controlled_patch_service.rollback_sandbox_patch(
            db, patch_proposal_id, **_actor(current_user)
        )
        return {
            "patch_proposal_id": row.patch_proposal_id,
            "status": row.status,
            "rollback_status": row.rollback_status,
            "message": "Sandbox patch rolled back to original snapshot.",
        }
    except controlled_patch_service.ControlledPatchError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
