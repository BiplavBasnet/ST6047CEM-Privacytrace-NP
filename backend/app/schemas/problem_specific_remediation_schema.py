"""Pydantic schemas for evidence-grounded problem-specific AI remediation output."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

RemediationType = Literal[
    "request_header_redaction",
    "request_body_redaction",
    "response_body_redaction",
    "redaction_order_fix",
    "sensitive_field_allowlist",
    "debug_logging_restriction",
    "query_parameter_removal",
    "proxy_log_configuration",
    "apm_capture_configuration",
    "error_handler_sanitisation",
    "report_export_masking",
    "secret_configuration_removal",
    "credential_rotation_required",
    "dependency_logging_configuration",
    "access_control_data_minimisation",
    "other",
]

ChangeType = Literal[
    "code_patch",
    "configuration_patch",
    "middleware_policy",
    "logging_policy",
    "test_modification",
    "other",
]


class RemediationDiagnosisOut(BaseModel):
    incident_id: str
    root_cause_analysis_id: str | None = None
    detected_sensitive_type: str | None = None
    exposure_location: str | None = None
    problem_statement: str = Field(min_length=1, max_length=4000)
    technical_mechanism: str = Field(min_length=1, max_length=4000)
    affected_service: str | None = None
    affected_endpoint: str | None = None
    affected_component: str | None = None
    affected_file_if_known: str | None = None
    affected_function_if_known: str | None = None
    affected_configuration_if_known: str | None = None
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    diagnosis_confidence: str
    diagnosis_limitations: list[str] = Field(default_factory=list)
    exact_source_location_known: bool = False
    human_review_required: bool = True


class PrimaryRemediationOut(BaseModel):
    remediation_id: str
    title: str = Field(min_length=1, max_length=512)
    remediation_type: RemediationType
    exact_problem_addressed: str = Field(min_length=1, max_length=4000)
    affected_component: str = Field(min_length=1, max_length=255)
    affected_file_if_known: str | None = None
    affected_function_if_known: str | None = None
    affected_configuration_if_known: str | None = None
    recommended_change: str = Field(min_length=1, max_length=8000)
    why_this_solution: str = Field(min_length=1, max_length=4000)
    evidence_alignment: str = Field(min_length=1, max_length=4000)
    why_not_broader_fix: str = Field(min_length=1, max_length=4000)
    expected_privacy_impact: str = Field(min_length=1, max_length=2000)
    operational_impact: str = Field(min_length=1, max_length=2000)
    implementation_risk: str = Field(min_length=1, max_length=2000)
    prerequisites: list[str] = Field(default_factory=list)
    implementation_steps: list[str] = Field(default_factory=list, min_length=1)
    tests_required: list[str] = Field(default_factory=list, min_length=1)
    retest_requirements: list[str] = Field(default_factory=list, min_length=1)
    rollback_plan: str = Field(min_length=1, max_length=4000)
    remediation_confidence: str
    confidence_limitations: list[str] = Field(default_factory=list)
    human_approval_required: bool = True


class ProposedChangeOut(BaseModel):
    change_type: ChangeType
    file_path: str = Field(min_length=1, max_length=1024)
    symbol_or_function: str | None = None
    base_content_hash: str | None = None
    change_summary: str = Field(min_length=1, max_length=4000)
    proposed_diff: str = Field(min_length=1, max_length=20000)
    why_each_change_is_needed: list[str] = Field(default_factory=list, min_length=1)
    expected_security_effect: str = Field(min_length=1, max_length=2000)
    side_effects: list[str] = Field(default_factory=list)
    tests_required: list[str] = Field(default_factory=list, min_length=1)


class AIProviderEnrichment(BaseModel):
    """Strict provider contract; deterministic remediation/source facts stay server-owned."""

    model_config = ConfigDict(extra="forbid")

    why_this_solution: str = Field(min_length=1, max_length=4000)
    evidence_alignment: str = Field(min_length=1, max_length=4000)
    limitations: list[str] = Field(default_factory=list, max_length=12)


class CurrentRemediationDiagnosisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    diagnosis_id: str
    incident_id: str
    root_cause_analysis_id: str | None
    review_decision_id: int | None
    generation_mode: str | None
    playbook_id: str | None
    playbook_version: str | None
    model_provider: str | None
    model_name: str | None
    prompt_template_version: str | None
    recommendation_policy_version: str | None
    status: str
    workflow_status: str
    problem_statement: str
    technical_mechanism: str
    affected_service: str | None
    affected_endpoint: str | None
    affected_component: str | None
    affected_file: str | None
    affected_function: str | None
    affected_configuration: str | None
    exact_source_location_known: bool
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    missing_evidence: list[str]
    limitations: list[str]
    diagnosis_confidence: str
    primary_remediation: dict[str, Any]
    alternative_remediations: list[dict[str, Any]]
    exact_change_available: bool
    proposed_change: dict[str, Any] | None
    created_at: datetime


class AIProblemSpecificRemediationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diagnosis_id: str | None = None
    generation_mode: Literal["playbook", "playbook_plus_ai", "fallback_playbook"] = "playbook"
    playbook_id: str = "privacytrace-playbook-v1"
    playbook_version: str = "1"
    model_provider: str = "deterministic_playbook"
    model_name: str = "privacytrace-playbook-v1"
    ai_failure_type: str | None = None
    source_claim_evidence_refs: list[str] = Field(default_factory=list)
    diagnosis: RemediationDiagnosisOut
    primary_remediation: PrimaryRemediationOut
    alternative_remediations: list[PrimaryRemediationOut] = Field(default_factory=list)
    exact_change_available: bool
    proposed_change: ProposedChangeOut | None = None
    tests: list[str] = Field(default_factory=list)
    retest_plan: dict[str, Any] = Field(default_factory=dict)
    rollback_plan: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    human_approval_required: bool = True

    @model_validator(mode="after")
    def validate_primary_and_change(self) -> AIProblemSpecificRemediationResponse:
        primary = self.primary_remediation
        if not primary.title.strip() or not primary.recommended_change.strip():
            raise ValueError("primary_remediation must include a non-empty title and recommended_change.")

        if self.exact_change_available:
            if self.proposed_change is None:
                raise ValueError("proposed_change is required when exact_change_available is true.")
        elif self.proposed_change is not None:
            raise ValueError("proposed_change must be omitted when exact_change_available is false.")

        if not self.human_approval_required:
            raise ValueError("human_approval_required must remain true for AI remediation output.")

        if primary.human_approval_required is not True:
            raise ValueError("primary_remediation.human_approval_required must remain true.")

        if self.diagnosis.human_review_required is not True:
            raise ValueError("diagnosis.human_review_required must remain true.")

        return self
