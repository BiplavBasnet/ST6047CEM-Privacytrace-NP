"""Input/output safety for problem-specific AI remediation payloads."""

from __future__ import annotations

import json
from typing import Any

from app.schemas.problem_specific_remediation_schema import AIProblemSpecificRemediationResponse
from app.services import audit_safety_service, report_safety_service


class RemediationAISafetyError(ValueError):
    pass


_FORBIDDEN_CLAIM_PHRASES = (
    "proven cause",
    "guaranteed fixed",
    "ai fixed",
    "production fix applied",
    "autonomous remediation",
    "confirmed blame",
    "developer fault",
)


def validate_problem_specific_response(response: AIProblemSpecificRemediationResponse) -> None:
    blob = json.dumps(response.model_dump(), default=str)
    hits = audit_safety_service.scan_text_for_sensitive(blob)
    if hits:
        raise RemediationAISafetyError(
            "Problem-specific remediation output contained sensitive-shaped values: "
            + ", ".join(hits[:5])
        )
    lower = blob.lower()
    for phrase in _FORBIDDEN_CLAIM_PHRASES:
        if phrase in lower:
            raise RemediationAISafetyError(
                f"Unsupported certainty/autonomy wording detected: {phrase}"
            )

    if not response.human_approval_required:
        raise RemediationAISafetyError("human_approval_required must remain true")
    if not response.diagnosis.human_review_required:
        raise RemediationAISafetyError("diagnosis.human_review_required must remain true")
    if not response.primary_remediation.human_approval_required:
        raise RemediationAISafetyError("primary_remediation.human_approval_required must remain true")

    if response.exact_change_available:
        if response.proposed_change is None or not response.proposed_change.file_path:
            raise RemediationAISafetyError(
                "exact_change_available=true requires a proposed_change with file_path"
            )
        if not response.diagnosis.exact_source_location_known:
            raise RemediationAISafetyError(
                "Cannot claim exact change when exact_source_location_known is false"
            )
    else:
        if response.diagnosis.affected_file_if_known and not response.diagnosis.exact_source_location_known:
            raise RemediationAISafetyError(
                "affected_file_if_known set without exact_source_location_known"
            )


def sanitize_free_text(value: str | None) -> str | None:
    if value is None:
        return None
    return report_safety_service.sanitize_export_text(value).value


def assert_no_raw_sensitive(payload: dict[str, Any]) -> None:
    blob = json.dumps(payload, default=str)
    hits = audit_safety_service.scan_text_for_sensitive(blob)
    if hits:
        raise RemediationAISafetyError(
            "Remediation context blocked: sensitive-shaped content detected ("
            + ", ".join(hits[:5])
            + ")"
        )
