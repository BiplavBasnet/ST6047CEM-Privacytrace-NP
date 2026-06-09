from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.schemas.privacy_impact_schema import DataCategory


class BreachAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    alert_id: str
    incident_id: str
    assessment_id: str
    alert_type: str
    severity: str
    status: str
    title: str
    summary: str
    reason_codes: list[str]
    affected_subject_count: int | None
    credential_exposure_present: bool
    requires_acknowledgement: bool
    triggered_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: int | None
    resolved_at: datetime | None
    resolved_by: int | None
    resolution_reason: str | None


class BreachAlertListResponse(BaseModel):
    alerts: list[BreachAlertRead]
    total: int


class AlertReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


class AffectedSubjectResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    directory_lookup_token: SecretStr
    subject_type: Literal["individual_customer", "merchant", "merchant_owner", "beneficiary", "employee", "service_account", "unknown_subject_type"] = "unknown_subject_type"
    affected_data_categories: list[DataCategory] = Field(default_factory=list, max_length=20)
    occurrence_count: int = Field(default=1, ge=1, le=1_000_000)
    credential_types: list[str] = Field(default_factory=list, max_length=20)


class AffectedSubjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    subject_reference_id: str
    incident_id: str
    subject_reference: str
    reference_method: str
    subject_type: str
    resolution_status: str
    affected_data_categories: list[str]
    occurrence_count: int
    credential_types: list[str]
    notification_eligibility: str
    created_at: datetime
    resolved_at: datetime | None


class AffectedSubjectListResponse(BaseModel):
    subjects: list[AffectedSubjectRead]
    total: int


class ContainmentActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    containment_action_id: str
    incident_id: str
    affected_subject_reference_id: str | None
    action_type: str
    credential_type: str | None
    status: str
    reason: str
    requires_approval: bool
    approved_by: int | None
    approved_at: datetime | None
    executed_by: int | None
    executed_at: datetime | None
    execution_reference: str | None
    result_summary: str | None
    failure_reason: str | None


class ContainmentActionListResponse(BaseModel):
    actions: list[ContainmentActionRead]
    total: int


class ActionApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


class CustomerNotificationDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    affected_subject_reference_id: str = Field(min_length=4, max_length=64)
    message_locale: str | None = Field(default=None, min_length=2, max_length=16)


class CustomerNotificationDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    notification_id: str
    incident_id: str
    assessment_id: str
    affected_subject_reference_id: str
    recommendation: str
    reason_codes: list[str]
    decision_rationale: str
    status: str
    draft_message: str
    message_locale: str
    created_by: int | None
    approved_by: int | None
    approved_at: datetime | None
    rejected_by: int | None
    rejected_at: datetime | None
    rejection_reason: str | None
    created_at: datetime
    updated_at: datetime


class CustomerNotificationListResponse(BaseModel):
    notifications: list[CustomerNotificationDecisionRead]
    total: int
    sending_enabled: bool


class NotificationQueueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["email", "webhook"]


class NotificationOutboxRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    outbox_id: str
    notification_id: str
    channel: str
    status: str
    attempt_count: int
    next_attempt_at: datetime | None
    last_error_category: str | None
    provider_message_reference: str | None
    created_at: datetime
    processed_at: datetime | None


class DeliveryAttemptRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    delivery_attempt_id: str
    attempt_number: int
    status: str
    error_category: str | None
    provider_message_reference: str | None
    attempted_at: datetime
    processed_at: datetime | None


class NotificationDeliveryStatusResponse(BaseModel):
    notification: CustomerNotificationDecisionRead
    outbox: list[NotificationOutboxRead]
    attempts: list[DeliveryAttemptRead]
    sending_enabled: bool
