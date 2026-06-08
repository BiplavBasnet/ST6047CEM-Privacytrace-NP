"""Phase 12.1 — privacy-safe final investigation report schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FinalReportMetadata(BaseModel):
    incident_id: str
    generated_at: datetime
    generated_by: str | None = None
    system_version: str | None = None
    report_format: str
    scenario_name: str | None = None
    report_ready: bool = False
    report_label: str = "Draft report - investigation stages remain incomplete."
    blocking_items: list[str] = Field(default_factory=list)
    report_version: int = 1
    root_cause_analysis_id: str | None = None
    root_cause_analysis_version: int | None = None
    evidence_snapshot_hash: str | None = None
    review_decision_id: int | None = None
    remediation_diagnosis_id: str | None = None
    remediation_action_id: str | None = None
    implementation_id: str | None = None
    patch_proposal_id: str | None = None
    test_execution_id: str | None = None
    controlled_retest_id: str | None = None
    fix_verification_id: int | None = None
    verification_outcome_id: str | None = None
    rollback_execution_id: str | None = None
    rollback_execution_ids: list[str] = Field(default_factory=list)
    workflow_chain_status: str = "blocked"
    disposition: str = "investigation_incomplete"
    taxonomy_version: str | None = None
    exposure_policy_version: str | None = None
    recommendation_policy_version: str | None = None


class FinalReportExecutiveSummary(BaseModel):
    incident_summary: str | None = None
    affected_service: str | None = None
    affected_endpoint: str | None = None
    severity: str | None = None
    top_likely_cause: str | None = None
    confidence_band: str | None = None
    evidence_strength_level: str | None = None
    confidence_cap: str | None = None
    confidence_limitations: list[str] = Field(default_factory=list)
    human_review_status: str
    fix_verification_status: str


class FinalReportIncidentSection(BaseModel):
    incident_id: str
    title: str
    affected_service: str | None = None
    affected_endpoint: str | None = None
    status: str
    severity: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    summary: str | None = None


class FinalReportDetection(BaseModel):
    detection_id: str
    sensitive_type: str
    masked_value: str
    confidence: float | None = None
    severity: str | None = None
    detector_name: str | None = None
    evidence_id: str | None = None
    created_at: datetime | None = None


class FinalReportEvidenceItem(BaseModel):
    evidence_id: str
    file_name: str
    evidence_type: str
    source_system: str | None = None
    file_hash: str | None = None
    upload_timestamp: datetime | None = None
    parsing_status: str
    role_in_investigation: str


class FinalReportNormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source_type: str
    service_name: str | None = None
    endpoint: str | None = None
    release_version: str | None = None
    event_type: str | None = None
    masked_message: str | None = None
    severity: str | None = None


class FinalReportRootCauseItem(BaseModel):
    rank: int | None = None
    cause_name: str
    confidence: float | None = None
    confidence_band: str | None = None
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    explanation: str | None = None
    score_breakdown: list[dict] = Field(default_factory=list)
    matched_signals: list[dict] = Field(default_factory=list)
    negative_signals: list[dict] = Field(default_factory=list)
    correlation_reasons: list[str] = Field(default_factory=list)
    contradicting_evidence: list[dict] = Field(default_factory=list)
    evidence_roles: list[dict] = Field(default_factory=list)
    suggested_actions: list[dict] = Field(default_factory=list)


class FinalReportScannerEvidence(BaseModel):
    scanner_evidence_id: str
    source_format: str
    finding_category: str | None = None
    detector_name: str | None = None
    masked_value: str | None = None
    source_file: str | None = None
    line_number: int | None = None
    severity: str | None = None
    confidence: float | None = None
    causal_relevance_score: float | None = None
    linked_incident_id: str | None = None


class FinalReportGuardedExplanation(BaseModel):
    explanation_text: str | None = None
    explanation_method: str | None = None
    safety_status: str | None = None
    overclaim_check: str | None = None
    human_review_required: bool = True
    not_generated_message: str | None = None


class FinalReportHumanReview(BaseModel):
    reviewer: str | None = None
    decision: str | None = None
    comment: str | None = None
    reason: str | None = None
    evidence_relied_on: list[str] = Field(default_factory=list)
    evidence_limitations: str | None = None
    missing_evidence_acknowledged: bool = False
    timestamp: datetime | None = None
    not_completed_message: str | None = None


class FinalReportFixVerification(BaseModel):
    verification_status: str | None = None
    checks_run: list[str] = Field(default_factory=list)
    passed_checks: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    evidence_used: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None
    not_completed_message: str | None = None


class FinalReportAuditEntry(BaseModel):
    actor: str | None = None
    action: str
    target_type: str | None = None
    target_id: str | None = None
    timestamp: datetime | None = None
    safe_details: dict[str, Any] = Field(default_factory=dict)


class FinalReportLiveAlertItem(BaseModel):
    alert_id: str
    alert_time: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    repeat_count: int = 1
    source_type: str | None = None
    source_name: str | None = None
    service_name: str | None = None
    endpoint: str | None = None
    severity: str | None = None
    status: str | None = None
    sensitive_types: list[str] = Field(default_factory=list)
    masked_values: list[str] = Field(default_factory=list)
    evidence_id: str | None = None


class FinalReportLiveMonitorSummary(BaseModel):
    source: str = "unknown"
    linked_alert_count: int = 0
    alerts: list[FinalReportLiveAlertItem] = Field(default_factory=list)
    evidence_strength: str = "weak"
    missing_evidence: list[str] = Field(default_factory=list)
    evidence_source_summary: dict[str, int] = Field(default_factory=dict)
    alert_to_incident_flow: str = (
        "No linked live alert was available at report generation time."
    )
    limitations: list[str] = Field(default_factory=list)
    note: str = (
        "Live privacy alerts are symptom evidence only. They show a possible "
        "exposure occurred, not why. Human review is required."
    )


class FinalInvestigationReport(BaseModel):
    metadata: FinalReportMetadata
    executive_summary: FinalReportExecutiveSummary
    incident: FinalReportIncidentSection
    live_monitor_summary: FinalReportLiveMonitorSummary = Field(
        default_factory=FinalReportLiveMonitorSummary
    )
    detections: list[FinalReportDetection] = Field(default_factory=list)
    evidence_chain: list[FinalReportEvidenceItem] = Field(default_factory=list)
    normalized_events: list[FinalReportNormalizedEvent] = Field(default_factory=list)
    root_cause_ranking: list[FinalReportRootCauseItem] = Field(default_factory=list)
    root_cause_evidence_strength: dict[str, Any] = Field(default_factory=dict)
    scannerbridge_evidence: list[FinalReportScannerEvidence] = Field(default_factory=list)
    ai_remediation_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    remediation_actions: list[str] = Field(default_factory=list)
    remediation_action_records: list[dict[str, Any]] = Field(default_factory=list)
    retest_evidence: list[FinalReportEvidenceItem] = Field(default_factory=list)
    guarded_explanation: FinalReportGuardedExplanation
    human_review: FinalReportHumanReview
    fix_verification: FinalReportFixVerification
    audit_summary: list[FinalReportAuditEntry] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    explainability_summary: dict[str, Any] = Field(default_factory=dict)
    evidence_graph_summary: dict[str, Any] = Field(default_factory=dict)
    safe_conclusion: str | None = None
    privacy_safety_controls: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    appendix: dict[str, Any] = Field(default_factory=dict)
    safety_warnings: list[str] = Field(default_factory=list)

