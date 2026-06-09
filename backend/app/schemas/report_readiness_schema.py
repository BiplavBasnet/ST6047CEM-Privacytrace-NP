from pydantic import BaseModel


class ReportReadinessChecks(BaseModel):
    incident_summary_ready: bool
    root_cause_available: bool
    human_review_recorded: bool
    remediation_recorded: bool
    retest_evidence_available: bool
    fix_verification_available: bool
    limitations_available: bool


class ReportReadinessResponse(BaseModel):
    incident_id: str
    report_ready: bool
    draft_report_available: bool
    report_label: str
    checks: ReportReadinessChecks
    blocking_items: list[str]
    warning_items: list[str]

