from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.models import EvidenceFile
from app.schemas.metric_schema import (
    EvaluationMetricRead,
    EvaluationMetricsListResponse,
    RunEvaluationRequest,
    RunEvaluationResponse,
)
from app.services import evaluation_metric_service

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/evaluation", response_model=EvaluationMetricsListResponse)
def get_evaluation_metrics(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_METRICS_READ))
    ],
    db: Session = Depends(get_db_session),
    scenario_name: str | None = "scenario_1",
):
    rows = evaluation_metric_service.list_evaluation_metrics(
        db, scenario_name=scenario_name, latest_only=True
    )
    items = [EvaluationMetricRead.model_validate(r) for r in rows]

    incident_id = None
    if scenario_name and scenario_name in evaluation_metric_service.SCENARIO_GROUND_TRUTH:
        incident_id = evaluation_metric_service.SCENARIO_GROUND_TRUTH[scenario_name][
            "incident_id"
        ]

    context: dict[str, int] = {}
    if incident_id:
        evidence_count = db.scalar(
            select(func.count())
            .select_from(EvidenceFile)
            .where(EvidenceFile.linked_incident_id == incident_id)
        )
        context["linked_evidence_files"] = int(evidence_count or 0)
        context["incidents_in_scope"] = 1

    return EvaluationMetricsListResponse(
        scenario_name=scenario_name,
        metrics=items,
        total=len(items),
        context_counts=context,
    )


@router.post("/evaluation/run", response_model=RunEvaluationResponse)
def run_evaluation_metrics(
    body: RunEvaluationRequest,
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_METRICS_RUN))
    ],
    db: Session = Depends(get_db_session),
):
    try:
        result = evaluation_metric_service.run_evaluation(
            db,
            scenario_name=body.scenario_name,
            requested_by=current_user.id,
        )
    except evaluation_metric_service.ScenarioNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    items = [EvaluationMetricRead.model_validate(m) for m in result.metrics]
    return RunEvaluationResponse(
        scenario_name=result.scenario_name,
        incident_id=result.incident_id,
        metrics_computed=len(items),
        metrics=items,
    )
