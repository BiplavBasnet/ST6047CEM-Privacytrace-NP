from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.schemas.llm_schema import (
    ExplainIncidentRequest,
    ExplainIncidentResponse,
    InvestigationOutput,
    LlmReportListResponse,
    LlmReportSummary,
)
from app.services import llm_investigation_service

router = APIRouter(prefix="/incidents", tags=["llm-explanation"])


@router.post("/{incident_id}/explain", response_model=ExplainIncidentResponse)
def explain_incident(
    incident_id: str,
    body: ExplainIncidentRequest,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_EXPLANATION_GENERATE)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        result = llm_investigation_service.explain_incident(
            db,
            incident_id,
            provider=body.provider,
            model=body.model,
            force_template=body.force_template,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if result.blocked:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Explanation blocked: input failed masked-only safety guard",
                "report_id": result.report_id,
                "safety_status": result.safety_status,
                "validation_errors": result.validation_errors,
            },
        )

    return ExplainIncidentResponse(
        report_id=result.report_id,
        incident_id=result.incident_id,
        provider_used=result.provider_used,
        model_name=result.model_name,
        safety_status=result.safety_status,
        validation_errors=result.validation_errors,
        output=InvestigationOutput.model_validate(result.output),
    )


@router.get("/{incident_id}/llm-reports", response_model=LlmReportListResponse)
def list_llm_reports(
    incident_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ))
    ],
    db: Session = Depends(get_db_session),
):
    from app.services.causality_engine import get_incident

    if not get_incident(db, incident_id):
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")

    reports = llm_investigation_service.list_llm_reports(db, incident_id)
    summaries: list[LlmReportSummary] = []
    for report in reports:
        output = llm_investigation_service.get_report_output_json(report)
        preview = (output.get("incident_summary") or "")[:200] or None
        likely = output.get("likely_cause_explanation") or ""
        cause_preview = likely[:120] if likely else None
        summaries.append(
            LlmReportSummary(
                report_id=report.report_id,
                incident_id=report.incident_id,
                provider_used=report.provider_used,
                model_name=report.model_name,
                safety_status=report.safety_status,
                created_at=report.created_at,
                incident_summary_preview=preview,
                top_likely_cause_preview=cause_preview,
            )
        )

    return LlmReportListResponse(
        incident_id=incident_id,
        reports=summaries,
        total=len(summaries),
    )
