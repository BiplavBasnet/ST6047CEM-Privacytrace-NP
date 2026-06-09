from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


RemediationActionType = Literal[
    "logging_middleware_change",
    "redaction_rule_update",
    "configuration_change",
    "debug_logging_disable",
    "proxy_logging_change",
    "apm_logging_change",
    "authorization_logging_change",
    "application_code_change",
    "dependency_update",
    "other",
]
RemediationStatus = Literal[
    "not_started",
    "assigned",
    "in_progress",
    "awaiting_retest",
    "completed",
    "cancelled",
]
RemediationPriority = Literal["low", "medium", "high", "critical"]


class RemediationActionCreate(BaseModel):
    action_type: RemediationActionType
    action_description: str = Field(min_length=3, max_length=2000)
    affected_component: str = Field(min_length=1, max_length=255)
    assigned_owner: str = Field(min_length=1, max_length=255)
    status: RemediationStatus = "not_started"
    priority: RemediationPriority = "medium"
    target_date: date | None = None
    retest_required: bool = True
    completion_notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def require_completion_notes(self):
        if self.status == "completed" and not (self.completion_notes or "").strip():
            raise ValueError("Completion notes are required when status is completed.")
        return self


class RemediationActionUpdate(BaseModel):
    action_type: RemediationActionType | None = None
    action_description: str | None = Field(default=None, min_length=3, max_length=2000)
    affected_component: str | None = Field(default=None, min_length=1, max_length=255)
    assigned_owner: str | None = Field(default=None, min_length=1, max_length=255)
    status: RemediationStatus | None = None
    priority: RemediationPriority | None = None
    target_date: date | None = None
    retest_required: bool | None = None
    completion_notes: str | None = Field(default=None, max_length=2000)


class RemediationActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    remediation_action_id: str
    incident_id: str
    action_type: str
    action_description: str
    affected_component: str
    assigned_owner: str
    status: str
    priority: str
    target_date: date | None
    retest_required: bool
    completion_notes: str | None
    created_by: int | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class RemediationActionListResponse(BaseModel):
    incident_id: str
    remediation_actions: list[RemediationActionResponse]
    total: int

