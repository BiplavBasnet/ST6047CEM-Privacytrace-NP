"""Remediated request logger — used as expected patch target content."""

from __future__ import annotations

import json
from typing import Mapping

AUTH_HEADER_NAME = "authorization"
REDACTED_AUTH_HEADER = "[REDACTED]"


def _redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() == AUTH_HEADER_NAME:
            safe[key] = REDACTED_AUTH_HEADER
        else:
            safe[key] = value
    return safe


def log_request_headers(headers: Mapping[str, str], path: str) -> str:
    """FIXED: redacts Authorization before serialisation."""
    payload = {"path": path, "headers": _redact_headers(headers)}
    return json.dumps(payload, sort_keys=True)


def contains_raw_token(log_line: str, token: str) -> bool:
    return token in log_line
