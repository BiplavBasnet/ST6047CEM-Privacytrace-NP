from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


EscalationLevel = Literal[
    "none",
    "team_lead",
    "incident_manager",
    "security_lead",
    "executive_review",
    "regulatory_review_recommended",
]


class AlertAssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assigned_user_id: int | None = Field(default=None, ge=1)
    assigned_team: str | None = Field(default=None, min_length=2, max_length=128)
    reason: str = Field(min_length=10, max_length=1000)
    acknowledgement_deadline: datetime | None = None
    containment_deadline: datetime | None = None
    escalation_deadline: datetime | None = None

    @model_validator(mode="after")
    def require_owner(self):
        if self.assigned_user_id is None and not (self.assigned_team or "").strip():
            raise ValueError("An assigned user or team is required.")
        return self


class AlertSuppressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=1000)
    expires_at: datetime | None = None
    policy_code: str | None = Field(default=None, max_length=128)
    privileged_override: bool = False


class AlertEscalateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    escalation_level: EscalationLevel
    reason: str = Field(min_length=10, max_length=1000)


class AlertReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=1000)


class OperationalAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    alert_id: str
    incident_id: str
    alert_type: str
    severity: str
    status: str
    title: str
    summary: str
    reason_codes: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    affected_subject_count: int | None = None
    credential_exposure_present: bool = False
    triggered_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    contained_at: datetime | None = None
    resolution_reason: str | None = None
    occurrence_count: int = 1
    duplicate_count: int = 0
    deduplication_window_started_at: datetime | None = None
    last_observed_at: datetime | None = None
    assigned_user_id: int | None = None
    assigned_team: str | None = None
    assigned_at: datetime | None = None
    acknowledgement_deadline: datetime | None = None
    containment_deadline: datetime | None = None
    escalation_deadline: datetime | None = None
    escalation_level: str = "none"
    suppression_reason: str | None = None
    suppression_started_at: datetime | None = None
    suppression_expires_at: datetime | None = None
    reopened_count: int = 0
    overdue: bool = False


class OperationalAlertListResponse(BaseModel):
    alerts: list[OperationalAlertRead]
    total: int


class AlertMetricsRead(BaseModel):
    total_alerts: int
    active_alerts: int
    unresolved_alert_count: int
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    duplicate_alerts_prevented: int
    suppressed_alerts: int
    false_positive_alerts: int
    acknowledged_alerts: int
    unacknowledged_past_deadline: int
    # Denominators for the corresponding median_* fields below. A None median
    # means the sample was empty (not zero elapsed seconds); the *_sample_size
    # fields make that denominator explicit rather than implied.
    acknowledged_sample_size: int
    contained_sample_size: int
    median_acknowledgement_seconds: float | None
    median_containment_seconds: float | None
    escalated_alerts: int
    reopened_alerts: int
    failed_containment_actions: int
    notification_delivery_failures: int
    generated_at: datetime


class OverdueAlertRead(BaseModel):
    alert: OperationalAlertRead
    overdue_reasons: list[str]
    recommended_escalation_level: EscalationLevel


class OverdueAlertListResponse(BaseModel):
    alerts: list[OverdueAlertRead]
    total: int


class AlertEvidenceLinkRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    alert_id: str
    evidence_id: str
    linked_at: datetime



