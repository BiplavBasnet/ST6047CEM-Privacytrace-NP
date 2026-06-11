"""Locate source/configuration evidence for problem-specific remediation."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence_file import EvidenceFile
from app.models.incident import Incident
from app.models.sast_finding import SastFinding
from app.services import (
    causality_engine,
    remediation_repository_safety_service,
    source_localisation_scoring_service,
)
from app.services.remediation_context_service import build_remediation_evidence_package


# ponytail: static map; upgrade path = load from root_cause_ontology / playbooks YAML
def _function_near_line(path: str, line_range: str | None) -> str | None:
    """Read the nearest def/class name above a SAST line. Never invent a path."""
    if not line_range:
        return None
    try:
        line_no = int(str(line_range).split("-", 1)[0])
        resolved = remediation_repository_safety_service.resolve_safe_repo_path(path)
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (ValueError, OSError):
        return None
    idx = min(max(line_no - 1, 0), len(lines) - 1)
    for current in range(idx, -1, -1):
        stripped = lines[current].lstrip()
        if stripped.startswith("def "):
            return stripped[4:].split("(", 1)[0].strip() or None
        if stripped.startswith("class "):
            return stripped[6:].split("(", 1)[0].split(":", 1)[0].strip() or None
    return None


_LIKELY_COMPONENT_BY_CAUSE: dict[str, str] = {
    "unsafe_request_body_logging": "request logging middleware",
    "unsafe_request_header_logging": "request header logging middleware",
    "authorization_header_logging": "request header logging middleware",
    "jwt_or_token_leakage": "request header logging middleware",
    "query_parameter_logging": "request logging middleware",
    "incomplete_redaction_rule": "log redaction pipeline",
    "debug_logging_enabled_after_deployment": "application logging configuration",
    "hardcoded_secret_or_api_key": "application configuration / secret management",
    "access_control_failure": "authorization layer",
    "sensitive_error_response_logging": "error handling middleware",
    "exception_stacktrace_exposure": "error handling middleware",
    "misconfigured_log_sink": "downstream log sink",
    "apm_or_reverse_proxy_log_exposure": "APM / reverse-proxy capture",
    "suspicious_dependency_introduced": "dependency integration layer",
    "fix_not_fully_verified": "remediation verification workflow",
}


def _locator_from_package(package: dict[str, Any]) -> dict[str, Any]:
    scored = source_localisation_scoring_service.select_best_localisation(package)
    cause_key = str(package.get("root_cause_category") or package.get("likely_root_cause") or "")
    likely_component = _LIKELY_COMPONENT_BY_CAUSE.get(
        cause_key,
        "affected application component (exact module not established)",
    )

    exact_known = bool(scored["exact_source_location_known"])
    file_path = scored.get("file_path")
    if exact_known and file_path:
        try:
            remediation_repository_safety_service.resolve_safe_repo_path(str(file_path))
        except ValueError:
            exact_known = False
            file_path = None
    function_or_class = scored.get("symbol_or_function") if exact_known else None
    if exact_known and file_path and not function_or_class:
        function_or_class = _function_near_line(str(file_path), scored.get("line_range"))

    limitations: list[str] = []
    if exact_known:
        limitations.append(
            "File path is established from ranked scanner/SAST/secret/CI changed-file evidence."
        )
        if scored.get("score") is not None:
            limitations.append(f"Localisation score={scored['score']:.2f}.")
    else:
        limitations.append(
            "Exact source file is not established above the localisation score threshold; "
            "component-level guidance only."
        )
        if scored.get("major_contradiction"):
            limitations.append(
                "Major contradiction between candidate source paths; exact location withheld."
            )
        limitations.append(
            "Provide repository mapping or scanner/change evidence identifying the implementation."
        )

    return {
        "exact_source_location_known": exact_known,
        "repository_reference": scored.get("repository_reference"),
        "source_location_type": scored.get("source_location_type"),
        "file_path": file_path,
        "function_or_class": function_or_class,
        "configuration_section": None,
        "line_range": scored.get("line_range"),
        "evidence_references": scored.get("evidence_references") or [],
        "localisation_confidence": scored.get("localisation_confidence") or "low",
        "localisation_score": scored.get("score"),
        "candidates": scored.get("candidates") or [],
        "limitations": limitations,
        "likely_component": likely_component,
    }


def locate_source_evidence(
    db: Session,
    incident_id: str,
    package: dict | None = None,
) -> dict[str, Any]:
    """Return source-localisation metadata without inventing paths."""
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    ctx = package if package is not None else build_remediation_evidence_package(db, incident_id)

    # Enrich from DB only when the evidence package omitted SAST rows.
    if not (ctx.get("sast_findings") or []):
        evidence_files = list(
            db.scalars(
                select(EvidenceFile).where(EvidenceFile.linked_incident_id == incident_id)
            ).all()
        )
        evidence_ids = [row.evidence_id for row in evidence_files]
        if evidence_ids:
            sast_rows = list(
                db.scalars(
                    select(SastFinding).where(
                        SastFinding.evidence_id.in_(evidence_ids),
                        SastFinding.file_path.is_not(None),
                    )
                ).all()
            )
            if sast_rows:
                ctx = {
                    **ctx,
                    "sast_findings": [
                        {
                            "evidence_id": s.evidence_id,
                            "file_path": s.file_path,
                            "line_number": s.line_number,
                            "rule_id": s.rule_id,
                            "finding_type": s.finding_type,
                            "message": s.message,
                        }
                        for s in sast_rows
                    ],
                }

    result = _locator_from_package(ctx)
    result["incident_id"] = incident_id

    if not result["likely_component"]:
        scores = causality_engine.list_root_cause_scores(db, incident_id)
        top = scores[0] if scores else None
        cause_key = (top.cause_name if top else "") or (top.likely_root_cause if top else "")
        result["likely_component"] = _LIKELY_COMPONENT_BY_CAUSE.get(
            cause_key,
            "affected application component (exact module not established)",
        )

    return result
