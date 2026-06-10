"""Phase 11.8 inbound vendor-format mapping into the canonical
PrivacyTraceIntegrationEvent shape.

Each mapping is intentionally conservative. We pull only well-known,
non-sensitive fields and leave the rest of the vendor payload alone.
Raw sensitive values are caught by the downstream
``integration_validation_service`` and rejected before persistence.

Reference mapping (informational, not vendor-certified):

OCSF (Open Cybersecurity Schema Framework)
  - metadata.uid           -> external_alert_id
  - severity               -> severity
  - time / event_time      -> event_time
  - service.name           -> service_name
  - http_request.url.path  -> endpoint
  - message / finding.title-> message
  - observables[*]         -> tags / evidence_reference

ECS (Elastic Common Schema)
  - event.id               -> external_alert_id
  - "@timestamp"           -> event_time
  - service.name           -> service_name
  - url.path               -> endpoint
  - event.severity / log.level -> severity
  - message                -> message
  - labels.*               -> tags

Splunk HEC
  - time                   -> event_time (epoch seconds or ISO)
  - source / sourcetype    -> source_tool (already supplied) / tags
  - event { ... }          -> mapped into canonical fields below
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.schemas.integration_schema import IntegrationEventIngestRequest

SUPPORTED_INBOUND_FORMATS = (
    "privacytrace_json",
    "ocsf_json",
    "ecs_json",
    "splunk_hec_json",
    "generic_json",
)


class UnsupportedSourceFormatError(ValueError):
    pass


class IntegrationMappingError(ValueError):
    pass


def _parse_event_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Splunk HEC ``time`` is epoch seconds.
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _normalise_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for k, v in value.items():
            if isinstance(v, (str, int, float)):
                out.append(f"{k}:{v}")
        return out
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (int, float)):
                out.append(str(item))
            elif isinstance(item, dict):
                # OCSF observable / generic dict
                name = item.get("name") or item.get("type") or "value"
                val = item.get("value") or item.get("uid") or ""
                if val:
                    out.append(f"{name}:{val}")
        return out
    return []


def _dig(payload: dict[str, Any] | None, *path: str) -> Any:
    current: Any = payload or {}
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _map_privacytrace(req: IntegrationEventIngestRequest) -> dict[str, Any]:
    """privacytrace_json uses top-level request fields directly."""
    return {
        "external_alert_id": req.external_alert_id,
        "external_incident_id": req.external_incident_id,
        "event_time": _parse_event_time(req.event_time),
        "service_name": req.service_name,
        "endpoint": req.endpoint,
        "environment": req.environment,
        "event_type": req.event_type,
        "sensitive_type": req.sensitive_type,
        "masked_value": req.masked_value,
        "severity": req.severity,
        "confidence": req.confidence,
        "message": req.message,
        "evidence_reference": req.evidence_reference,
        "source_ip": req.source_ip,
        "destination_ip": req.destination_ip,
        "user_or_actor": req.user_or_actor,
        "trace_id": req.trace_id,
        "tags": list(req.tags or []),
        "linked_incident_id": req.linked_incident_id,
    }


def _map_ocsf(req: IntegrationEventIngestRequest) -> dict[str, Any]:
    payload = req.payload or {}
    base = _map_privacytrace(req)
    base["external_alert_id"] = (
        req.external_alert_id
        or _dig(payload, "metadata", "uid")
        or _dig(payload, "finding", "uid")
        or _dig(payload, "uid")
    )
    base["event_time"] = base["event_time"] or _parse_event_time(
        payload.get("time") or payload.get("event_time")
    )
    base["service_name"] = base["service_name"] or _dig(payload, "service", "name")
    base["endpoint"] = base["endpoint"] or _dig(
        payload, "http_request", "url", "path"
    )
    base["severity"] = base["severity"] or payload.get("severity")
    base["message"] = base["message"] or payload.get("message") or _dig(
        payload, "finding", "title"
    )
    base["confidence"] = base["confidence"] or payload.get("confidence")
    extra_tags = _normalise_tags(payload.get("observables"))
    base["tags"] = list(base["tags"] or []) + extra_tags
    return base


def _map_ecs(req: IntegrationEventIngestRequest) -> dict[str, Any]:
    payload = req.payload or {}
    base = _map_privacytrace(req)
    base["external_alert_id"] = (
        req.external_alert_id
        or _dig(payload, "event", "id")
        or _dig(payload, "event", "reference")
    )
    base["event_time"] = base["event_time"] or _parse_event_time(
        payload.get("@timestamp") or _dig(payload, "event", "created")
    )
    base["service_name"] = base["service_name"] or _dig(payload, "service", "name")
    base["endpoint"] = base["endpoint"] or _dig(payload, "url", "path")
    base["severity"] = (
        base["severity"]
        or _dig(payload, "event", "severity")
        or payload.get("log.level")
        or _dig(payload, "log", "level")
    )
    base["message"] = base["message"] or payload.get("message")
    extra_tags = _normalise_tags(payload.get("labels"))
    base["tags"] = list(base["tags"] or []) + extra_tags
    base["trace_id"] = base["trace_id"] or _dig(payload, "trace", "id")
    return base


def _map_splunk_hec(req: IntegrationEventIngestRequest) -> dict[str, Any]:
    payload = req.payload or {}
    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    base = _map_privacytrace(req)
    base["external_alert_id"] = (
        req.external_alert_id
        or event.get("external_alert_id")
        or event.get("alert_id")
        or event.get("id")
    )
    base["event_time"] = base["event_time"] or _parse_event_time(payload.get("time"))
    base["service_name"] = base["service_name"] or event.get("service_name") or event.get(
        "service"
    )
    base["endpoint"] = base["endpoint"] or event.get("endpoint") or event.get("url_path")
    base["severity"] = base["severity"] or event.get("severity")
    base["confidence"] = base["confidence"] or event.get("confidence")
    base["message"] = base["message"] or event.get("message")
    base["sensitive_type"] = base["sensitive_type"] or event.get("sensitive_type")
    base["masked_value"] = base["masked_value"] or event.get("masked_value")
    base["evidence_reference"] = base["evidence_reference"] or event.get(
        "evidence_reference"
    )
    base["tags"] = list(base["tags"] or []) + _normalise_tags(event.get("tags"))
    base["source_ip"] = base["source_ip"] or event.get("source_ip")
    base["destination_ip"] = base["destination_ip"] or event.get("destination_ip")
    base["user_or_actor"] = base["user_or_actor"] or event.get("user_or_actor")
    base["trace_id"] = base["trace_id"] or event.get("trace_id")
    return base


def _map_generic(req: IntegrationEventIngestRequest) -> dict[str, Any]:
    payload = req.payload or {}
    base = _map_privacytrace(req)
    for key in (
        "external_alert_id",
        "external_incident_id",
        "service_name",
        "endpoint",
        "environment",
        "event_type",
        "sensitive_type",
        "masked_value",
        "severity",
        "confidence",
        "message",
        "evidence_reference",
        "source_ip",
        "destination_ip",
        "user_or_actor",
        "trace_id",
        "linked_incident_id",
    ):
        if base.get(key) is None and payload.get(key) is not None:
            base[key] = payload.get(key)
    if base["event_time"] is None:
        base["event_time"] = _parse_event_time(payload.get("event_time"))
    base["tags"] = list(base["tags"] or []) + _normalise_tags(payload.get("tags"))
    return base


_MAPPERS = {
    "privacytrace_json": _map_privacytrace,
    "ocsf_json": _map_ocsf,
    "ecs_json": _map_ecs,
    "splunk_hec_json": _map_splunk_hec,
    "generic_json": _map_generic,
}


def map_inbound_to_canonical(req: IntegrationEventIngestRequest) -> dict[str, Any]:
    """Return the canonical event dict for the given inbound request.

    Raises ``UnsupportedSourceFormatError`` if the source_format is
    unknown so the router can return a clear 400 response.
    """
    fmt = (req.source_format or "").strip().lower()
    if fmt not in _MAPPERS:
        raise UnsupportedSourceFormatError(
            f"Unsupported source_format: {req.source_format!r}. "
            f"Supported: {', '.join(SUPPORTED_INBOUND_FORMATS)}"
        )
    mapper = _MAPPERS[fmt]
    canonical = mapper(req)
    # Ensure tags are unique strings preserving order.
    seen: set[str] = set()
    canonical["tags"] = [
        t for t in canonical.get("tags", []) if isinstance(t, str) and not (t in seen or seen.add(t))
    ]
    canonical["source_format"] = fmt
    canonical["source_tool"] = req.source_tool
    return canonical
