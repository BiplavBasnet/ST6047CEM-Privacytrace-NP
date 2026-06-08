from typing import Literal

from pydantic import BaseModel


WorkflowStageCode = Literal[
    "overview",
    "root_cause",
    "human_review",
    "remediation",
    "fix_verification",
    "final_report",
]
WorkflowStageStatus = Literal["pending", "ready", "complete", "blocked"]


class WorkflowNextAction(BaseModel):
    code: str
    label: str
    description: str
    target: str
    priority: Literal["low", "medium", "high"] = "medium"
    blocked: bool = False
    blocked_reason: str | None = None


class WorkflowStage(BaseModel):
    code: WorkflowStageCode
    label: str
    status: WorkflowStageStatus
    available: bool
    completed: bool
    blocked_reason: str | None = None


class IncidentWorkflowState(BaseModel):
    incident_id: str
    current_stage: WorkflowStageCode
    overall_status: str
    next_action: WorkflowNextAction
    stages: list[WorkflowStage]
    # Provenance facts (optional for older clients)
    current_root_cause_analysis_id: str | None = None
    current_root_cause_analysis_version: int | None = None
    current_root_cause_analysis_stale: bool | None = None
    workflow_chain_status: Literal["current", "stale", "blocked"] = "blocked"
    review_progression_valid: bool | None = None
    diagnosis_id: str | None = None
    diagnosis_generation_mode: str | None = None
    remediation_action_id: str | None = None
    remediation_action_status: str | None = None
    patch_status: str | None = None
    test_execution_status: str | None = None
    verification_outcome: str | None = None
    blocked_reasons: list[str] = []
    lifecycle_phase: str = "OPEN"
