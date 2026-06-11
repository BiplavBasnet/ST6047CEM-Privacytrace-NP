"""Phase 11.8 outbound SOC export service.

Given an incident, this service produces safe, vendor-neutral export
representations:

  * privacytrace_json     – the canonical PrivacyTrace summary
  * ocsf_json             – OCSF-style finding (basic mapping)
  * ecs_json              – ECS-style event (basic mapping)
  * splunk_hec_json       – Splunk HEC wrapper around the safe summary
  * cef_like              – CEF-style single-line text record
  * leef_like             – LEEF-style single-line text record
  * rfc5424_syslog_like   – RFC 5424 syslog-style line with structured data

The exporter never includes raw sensitive values, raw logs, tokens,
passwords, password hashes, private keys, decrypted payloads, raw LLM
prompts or overclaim phrases. Each export passes through
:func:`report_safety_service.validate_text_blob` as a defence-in-depth
check before it is returned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.services import report_safety_service, report_service
from app.services.report_safety_service import ReportSafetyError

PRIVACYTRACE_VENDOR = "PrivacyTrace-NP"
PRIVACYTRACE_VERSION = "1.0"
PRIVACYTRACE_SIGNATURE = "privacy_exposure"
PRIVACYTRACE_NAME = "Sensitive Data Exposure Trace"


SUPPORTED_OUTBOUND_FORMATS = (
    "privacytrace_json",
    "ocsf_json",
    "ecs_json",
    "splunk_hec_json",
    "cef_like",
    "leef_like",
    "rfc5424_syslog_like",
)


@dataclass
class IncidentExport:
    incident_id: str
    format: str
    content_type: str
    body: str | dict[str, Any]
    generated_at: datetime


class UnsupportedExportFormatError(ValueError):
    pass


def _to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _evidence_ids(content: dict[str, Any]) -> list[str]:
    ids: list[str] = list(content.get("linked_evidence_ids") or [])
    for det in content.get("masked_detections") or []:
        eid = det.get("evidence_id")
        if eid and eid not in ids:
            ids.append(eid)
    return ids


def _build_safe_summary(content: dict[str, Any]) -> dict[str, Any]:
    """Build the universal, vendor-neutral safe incident summary."""
    top = content.get("top_likely_root_cause")
    causes = content.get("likely_root_causes") or []
    ranking = [
        {
            "rank": cause.get("rank"),
            "likely_root_cause": cause.get("likely_root_cause"),
            "confidence_band": cause.get("confidence_band"),
            "supporting_evidence_ids": list(cause.get("supporting_evidence_ids") or []),
        }
        for cause in causes
    ]
    fix = content.get("fix_verification") or {}
    review_decisions = content.get("human_review_decisions") or []
    return {
        "incident_id": content.get("incident_id"),
        "title": content.get("title"),
        "status": content.get("status"),
        "severity": content.get("severity"),
        "affected_service": content.get("affected_service"),
        "affected_endpoint": content.get("affected_endpoint"),
        "masked_detections": [
            {
                "detection_id": d.get("detection_id"),
                "sensitive_type": d.get("sensitive_type"),
                "masked_value": d.get("masked_value"),
                "evidence_id": d.get("evidence_id"),
                "severity": d.get("severity"),
                "confidence": d.get("confidence"),
            }
            for d in (content.get("masked_detections") or [])
        ],
        "sensitive_types": sorted(
            {
                d.get("sensitive_type")
                for d in (content.get("masked_detections") or [])
                if d.get("sensitive_type")
            }
        ),
        "linked_evidence_ids": _evidence_ids(content),
        "top_likely_cause": top,
        "root_cause_ranking": ranking,
        "confidence_band": content.get("confidence_band"),
        "confidence_score": content.get("confidence_score"),
        "missing_evidence": list(content.get("missing_evidence") or []),
        "human_review_status": (
            review_decisions[-1].get("decision")
            if review_decisions
            else "pending"
        ),
        "human_review_required": True,
        "fix_verification_status": fix.get("verification_status") or "not_run",
        "report_reference": (
            f"/reports/incidents/{content.get('incident_id')}"
            if content.get("incident_id")
            else None
        ),
        "privacytrace_link": (
            f"/incidents/{content.get('incident_id')}"
            if content.get("incident_id")
            else None
        ),
        "generated_at": _to_iso(content.get("generated_at")) or _to_iso(
            datetime.now(timezone.utc)
        ),
        "disclaimer": (
            "PrivacyTrace-NP reports likely causes supported by evidence and "
            "requires human review before closure. This export contains "
            "masked values only."
        ),
    }


def _assert_safe_text(text: str) -> None:
    result = report_safety_service.validate_text_blob(text)
    if not result.safe:
        raise ReportSafetyError(
            result.message
            or "Export failed safety validation; raw sensitive values or "
            "unsupported certainty phrases are not allowed."
        )


def _assert_safe_payload(payload: dict[str, Any]) -> None:
    _assert_safe_text(json.dumps(payload, default=str))


# ---------------------------------------------------------------------------
# Format builders
# ---------------------------------------------------------------------------


def _privacytrace_json(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "privacytrace_json",
        "schema_version": "1.0",
        "incident": summary,
    }


def _ocsf_json(summary: dict[str, Any]) -> dict[str, Any]:
    """OCSF-style finding (basic mapping, not vendor-certified)."""
    observables = [
        {"name": "evidence_id", "type": "Other", "value": eid}
        for eid in summary.get("linked_evidence_ids") or []
    ]
    return {
        "schema": "ocsf_json",
        "category_uid": 2,  # Findings category in OCSF
        "class_uid": 2004,  # Application Activity / Finding (illustrative)
        "metadata": {
            "uid": summary.get("incident_id"),
            "version": "1.0.0",
            "product": {"name": PRIVACYTRACE_VENDOR, "vendor_name": PRIVACYTRACE_VENDOR},
        },
        "severity": summary.get("severity"),
        "status": summary.get("status"),
        "confidence": summary.get("confidence_score"),
        "service": {"name": summary.get("affected_service")},
        "http_request": {"url": {"path": summary.get("affected_endpoint")}},
        "finding": {
            "uid": summary.get("incident_id"),
            "title": summary.get("top_likely_cause") or summary.get("title"),
            "desc": summary.get("disclaimer"),
        },
        "observables": observables,
        "unmapped": {
            "evidence_ids": summary.get("linked_evidence_ids") or [],
            "root_cause_ranking": summary.get("root_cause_ranking") or [],
            "missing_evidence": summary.get("missing_evidence") or [],
            "human_review_status": summary.get("human_review_status"),
            "fix_verification_status": summary.get("fix_verification_status"),
            "masked_detections": summary.get("masked_detections") or [],
            "sensitive_types": summary.get("sensitive_types") or [],
            "report_reference": summary.get("report_reference"),
            "privacytrace_link": summary.get("privacytrace_link"),
        },
        "time": summary.get("generated_at"),
    }


def _ecs_json(summary: dict[str, Any]) -> dict[str, Any]:
    """ECS-style event (basic mapping, not vendor-certified)."""
    return {
        "schema": "ecs_json",
        "@timestamp": summary.get("generated_at"),
        "event": {
            "id": summary.get("incident_id"),
            "kind": "alert",
            "category": ["threat", "configuration"],
            "action": "privacytrace_sensitive_data_exposure",
            "severity": summary.get("severity"),
            "outcome": summary.get("status"),
        },
        "service": {"name": summary.get("affected_service")},
        "url": {"path": summary.get("affected_endpoint")},
        "labels": {
            "privacytrace_likely_cause": summary.get("top_likely_cause"),
            "privacytrace_confidence_band": summary.get("confidence_band"),
            "privacytrace_human_review_status": summary.get("human_review_status"),
            "privacytrace_fix_verification_status": summary.get(
                "fix_verification_status"
            ),
            "evidence_ids": ",".join(summary.get("linked_evidence_ids") or []),
            "sensitive_types": ",".join(summary.get("sensitive_types") or []),
        },
        "related": {"hash": summary.get("linked_evidence_ids") or []},
        "privacytrace": summary,
    }


def _splunk_hec_json(summary: dict[str, Any]) -> dict[str, Any]:
    generated_at = summary.get("generated_at")
    epoch: float | None = None
    if generated_at:
        try:
            ts = generated_at[:-1] + "+00:00" if generated_at.endswith("Z") else generated_at
            dt = datetime.fromisoformat(ts)
            epoch = dt.timestamp()
        except (ValueError, AttributeError):
            epoch = None
    return {
        "schema": "splunk_hec_json",
        "time": epoch,
        "host": "privacytrace-np",
        "source": "privacytrace-np",
        "sourcetype": "privacytrace:incident",
        "event": summary,
    }


def _escape_cef(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def _cef_like(summary: dict[str, Any]) -> str:
    """CEF-like single-line text record (ArcSight-style)."""
    header = "|".join(
        [
            "CEF:0",
            PRIVACYTRACE_VENDOR,
            PRIVACYTRACE_VENDOR,
            PRIVACYTRACE_VERSION,
            PRIVACYTRACE_SIGNATURE,
            PRIVACYTRACE_NAME,
            str(summary.get("severity") or "medium"),
        ]
    )
    extensions = " ".join(
        filter(
            None,
            [
                f"cs1Label=incident_id cs1={_escape_cef(summary.get('incident_id'))}",
                f"cs2Label=likely_cause cs2={_escape_cef(summary.get('top_likely_cause'))}",
                f"cs3Label=confidence_band cs3={_escape_cef(summary.get('confidence_band'))}",
                f"cs4Label=human_review_status cs4={_escape_cef(summary.get('human_review_status'))}",
                f"cs5Label=fix_verification_status cs5={_escape_cef(summary.get('fix_verification_status'))}",
                f"act=privacytrace_sensitive_data_exposure",
                f"app={_escape_cef(summary.get('affected_service'))}",
                f"request={_escape_cef(summary.get('affected_endpoint'))}",
                f"evidence_ids={_escape_cef(','.join(summary.get('linked_evidence_ids') or []))}",
                f"sensitive_types={_escape_cef(','.join(summary.get('sensitive_types') or []))}",
            ],
        )
    )
    return f"{header}|{extensions}"


def _escape_leef(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\t", " ").replace("|", "/")


def _leef_like(summary: dict[str, Any]) -> str:
    """LEEF-like single-line text record (QRadar-style)."""
    header = "|".join(
        [
            "LEEF:2.0",
            PRIVACYTRACE_VENDOR,
            PRIVACYTRACE_VENDOR,
            PRIVACYTRACE_VERSION,
            PRIVACYTRACE_SIGNATURE,
        ]
    )
    fields = "\t".join(
        [
            f"severity={_escape_leef(summary.get('severity'))}",
            f"incident_id={_escape_leef(summary.get('incident_id'))}",
            f"likely_cause={_escape_leef(summary.get('top_likely_cause'))}",
            f"confidence_band={_escape_leef(summary.get('confidence_band'))}",
            f"human_review_status={_escape_leef(summary.get('human_review_status'))}",
            f"fix_verification_status={_escape_leef(summary.get('fix_verification_status'))}",
            f"service={_escape_leef(summary.get('affected_service'))}",
            f"endpoint={_escape_leef(summary.get('affected_endpoint'))}",
            f"evidence_ids={_escape_leef(','.join(summary.get('linked_evidence_ids') or []))}",
            f"sensitive_types={_escape_leef(','.join(summary.get('sensitive_types') or []))}",
        ]
    )
    return f"{header}|{fields}"


def _escape_sd(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _rfc5424_syslog_like(summary: dict[str, Any]) -> str:
    """RFC5424 syslog-like single-line record (generic SOC forwarding)."""
    timestamp = summary.get("generated_at") or _to_iso(datetime.now(timezone.utc))
    hostname = "privacytrace-np"
    appname = PRIVACYTRACE_VENDOR.replace(" ", "-")
    msgid = "ID47"
    sd_id = "privacytrace@privacytrace-np"
    sd_fields = " ".join(
        [
            f'incident_id="{_escape_sd(summary.get("incident_id"))}"',
            f'severity="{_escape_sd(summary.get("severity"))}"',
            f'service="{_escape_sd(summary.get("affected_service"))}"',
            f'endpoint="{_escape_sd(summary.get("affected_endpoint"))}"',
            f'likely_cause="{_escape_sd(summary.get("top_likely_cause"))}"',
            f'confidence_band="{_escape_sd(summary.get("confidence_band"))}"',
            f'human_review_status="{_escape_sd(summary.get("human_review_status"))}"',
            f'fix_verification_status="{_escape_sd(summary.get("fix_verification_status"))}"',
            f'evidence_ids="{_escape_sd(",".join(summary.get("linked_evidence_ids") or []))}"',
        ]
    )
    structured = f"[{sd_id} {sd_fields}]"
    msg = (
        f"PrivacyTrace-NP incident {summary.get('incident_id')} "
        f"likely cause: {summary.get('top_likely_cause')}. "
        "Masked detections only; human review required."
    )
    return f"<134>1 {timestamp} {hostname} {appname} - {msgid} {structured} {msg}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_supported_formats() -> list[dict[str, str]]:
    return [
        {
            "format_id": "privacytrace_json",
            "direction": "outbound",
            "title": "PrivacyTrace JSON",
            "description": "Canonical PrivacyTrace-NP safe incident summary in JSON.",
        },
        {
            "format_id": "ocsf_json",
            "direction": "outbound",
            "title": "OCSF-style JSON",
            "description": "Open Cybersecurity Schema Framework style mapping (basic, adapter-based).",
        },
        {
            "format_id": "ecs_json",
            "direction": "outbound",
            "title": "ECS-style JSON",
            "description": "Elastic Common Schema style mapping (basic, adapter-based).",
        },
        {
            "format_id": "splunk_hec_json",
            "direction": "outbound",
            "title": "Splunk HEC-style JSON",
            "description": "HTTP Event Collector style wrapper (basic, adapter-based).",
        },
        {
            "format_id": "cef_like",
            "direction": "outbound",
            "title": "CEF-like",
            "description": "ArcSight-style single-line text record. Adapter-based, not officially certified.",
        },
        {
            "format_id": "leef_like",
            "direction": "outbound",
            "title": "LEEF-like",
            "description": "QRadar-style single-line text record. Adapter-based, not officially certified.",
        },
        {
            "format_id": "rfc5424_syslog_like",
            "direction": "outbound",
            "title": "RFC5424 syslog-like",
            "description": "Generic syslog-style record with structured data. Adapter-based.",
        },
    ]


def export_incident(
    db: Session,
    *,
    incident_id: str,
    fmt: str,
) -> IncidentExport:
    fmt = (fmt or "").strip().lower()
    if fmt not in SUPPORTED_OUTBOUND_FORMATS:
        raise UnsupportedExportFormatError(
            f"Unsupported export format: {fmt!r}. "
            f"Supported: {', '.join(SUPPORTED_OUTBOUND_FORMATS)}"
        )

    content = report_service.build_incident_report_content(db, incident_id)
    summary = _build_safe_summary(content)
    _assert_safe_payload(summary)

    generated_at = datetime.now(timezone.utc)
    if fmt == "privacytrace_json":
        body: str | dict[str, Any] = _privacytrace_json(summary)
        content_type = "application/json"
    elif fmt == "ocsf_json":
        body = _ocsf_json(summary)
        content_type = "application/json"
    elif fmt == "ecs_json":
        body = _ecs_json(summary)
        content_type = "application/json"
    elif fmt == "splunk_hec_json":
        body = _splunk_hec_json(summary)
        content_type = "application/json"
    elif fmt == "cef_like":
        body = _cef_like(summary)
        content_type = "text/plain"
    elif fmt == "leef_like":
        body = _leef_like(summary)
        content_type = "text/plain"
    elif fmt == "rfc5424_syslog_like":
        body = _rfc5424_syslog_like(summary)
        content_type = "text/plain"
    else:  # pragma: no cover - guarded above
        raise UnsupportedExportFormatError(fmt)

    # Defence-in-depth: re-scan the rendered output.
    if isinstance(body, dict):
        _assert_safe_payload(body)
    else:
        _assert_safe_text(body)

    return IncidentExport(
        incident_id=incident_id,
        format=fmt,
        content_type=content_type,
        body=body,
        generated_at=generated_at,
    )
