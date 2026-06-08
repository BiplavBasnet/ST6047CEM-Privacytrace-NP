"""Evidence type to parser registry."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from app.models.enums import EvidenceType
from app.parsers.access_parser import parse_access_file
from app.parsers.base import ParsedEventDraft
from app.parsers.deployment_parser import parse_deployment_file
from app.parsers.log_parser import parse_log_file
from app.parsers.scan_parser import parse_scan_file
from app.parsers.trivy_parser import parse_trivy_file

ParserFn = Callable[..., list[ParsedEventDraft]]

_UNSUPPORTED = {
    EvidenceType.SIEM_ALERT,
    EvidenceType.FIXED_SCAN,
}

_REGISTRY: dict[EvidenceType, ParserFn] = {
    EvidenceType.API_LOG: parse_log_file,
    EvidenceType.RUNTIME_LOG: parse_log_file,
    EvidenceType.FIXED_LOG: parse_log_file,
    EvidenceType.SEMGREP_REPORT: parse_scan_file,
    EvidenceType.GITLEAKS_REPORT: parse_scan_file,
    EvidenceType.DEPLOYMENT_LOG: parse_deployment_file,
    EvidenceType.ACCESS_EVENT: parse_access_file,
    EvidenceType.TRIVY_REPORT: parse_trivy_file,
}


def get_parser(evidence_type: EvidenceType) -> ParserFn:
    if evidence_type in _UNSUPPORTED:
        raise ValueError(
            f"Parsing not implemented for evidence type: {evidence_type.value}. "
            "Supported types: api_log, runtime_log, fixed_log, semgrep_report, "
            "gitleaks_report, deployment_log, access_event, trivy_report."
        )
    parser = _REGISTRY.get(evidence_type)
    if parser is None:
        raise ValueError(f"No parser registered for evidence type: {evidence_type.value}")
    return parser


def parse_evidence_file(
    path: Path,
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    linked_incident_id: str | None,
) -> list[ParsedEventDraft]:
    parser = get_parser(evidence_type)
    return parser(
        path,
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        linked_incident_id=linked_incident_id,
    )
