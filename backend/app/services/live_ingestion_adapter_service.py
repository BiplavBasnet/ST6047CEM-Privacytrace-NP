"""Input adapters for Live Privacy Monitor event payloads."""

from __future__ import annotations

import json

from app.schemas.live_monitor_schema import SUPPORTED_LIVE_SOURCE_FORMATS, LiveMonitorEventRequest


class UnsupportedLiveMonitorFormatError(ValueError):
    pass


def validate_source_format(source_format: str) -> str:
    fmt = (source_format or "generic_json").strip().lower()
    if fmt not in SUPPORTED_LIVE_SOURCE_FORMATS:
        raise UnsupportedLiveMonitorFormatError(
            "Unsupported live monitor source_format. Use an adapter listed by /live-monitor/status."
        )
    return fmt


def extract_event_text(event: LiveMonitorEventRequest) -> str:
    validate_source_format(event.source_format)
    parts = [event.message or ""]
    if event.metadata:
        parts.append(json.dumps(event.metadata, sort_keys=True, default=str))
    if event.payload:
        parts.append(json.dumps(event.payload, sort_keys=True, default=str))
    return "\n".join(part for part in parts if part).strip()
