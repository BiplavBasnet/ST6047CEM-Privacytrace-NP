from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ImplementationCreate(BaseModel):
    remediation_action_id: str
    implementation_mode: Literal[
        "manual", "external_configuration_change"
    ]
    implementation_summary: str = Field(min_length=1, max_length=2000)
    change_reference_safe: str | None = Field(default=None, max_length=1024)
    change_hash: str | None = Field(default=None, max_length=128)


class ImplementationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    implementation_id: str
    incident_id: str
    remediation_action_id: str
    patch_proposal_id: str | None
    implementation_mode: str
    change_reference_safe: str | None
    change_hash: str | None
    implementation_summary: str
    status: str
    implemented_at: datetime
    workflow_status: str


class ControlledRetestCreate(BaseModel):
    implementation_id: str
    test_execution_id: str
    original_finding_id: str
    source_type: str = Field(min_length=1, max_length=128)
    synthetic_output: str = Field(min_length=1, max_length=100_000)
    service_name: str | None = Field(default=None, max_length=255)
    endpoint: str | None = Field(default=None, max_length=512)
    exposure_location: str | None = Field(default=None, max_length=128)
    component: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=128)


class ControlledRetestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    controlled_retest_id: str
    incident_id: str
    implementation_id: str
    test_execution_id: str
    original_finding_id: str
    retest_finding_id: str | None
    service_name: str | None
    endpoint: str | None
    exposure_location: str | None
    sensitive_type: str | None
    component: str | None
    environment: str | None
    dimensions_match: bool
    raw_exposure_after_change: bool | None
    finding_count: int
    safety_status: str
    status: str
    completed_at: datetime
    workflow_status: str


class TestExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    execution_id: str
    implementation_id: str | None
    remediation_action_id: str | None
    test_profile: str
    status: str
    safety_status: str | None
    raw_leakage_count: int | None
    safe_output_summary: str | None
    workflow_status: str


class RemediationLifecycleStatus(BaseModel):
    incident_id: str
    implementation: ImplementationRead | None
    test_execution: TestExecutionRead | None
    controlled_retest: ControlledRetestRead | None
    fix_verification_id: int | None
    verification_outcome_id: str | None
    verification_result: str | None
    verified_case_id: str | None
    learning_eligible: bool
    workflow_chain_status: str
    lifecycle_phase: str = "OPEN"
    rollback_execution_id: str | None = None
    rollback_status: str | None = None
    rollback_verification: str | None = None
    rollback_verified: bool | None = None
