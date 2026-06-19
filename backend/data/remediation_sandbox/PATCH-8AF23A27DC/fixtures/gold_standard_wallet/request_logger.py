"""Synthetic vulnerable request-header logger for gold-standard evaluation.

GROUND TRUTH — synthetic only, never real credentials:
- Sensitive type: bearer_token
- Exposure location: request_header_log
- Service: synthetic-wallet-service
- Endpoint: /wallet/transfer
- Root cause: unsafe_request_header_logging
- Component: request logging middleware
- File: fixtures/gold_standard_wallet/request_logger.py
- Function: log_request_headers
- Remediation: redact Authorization before serialisation
"""

from __future__ import annotations

import json
from typing import Mapping

AUTH_HEADER_NAME = "authorization"
REDACTED_AUTH_HEADER = "[REDACTED]"


def log_request_headers(headers: Mapping[str, str], path: str) -> str:
    """VULNERABLE: serialises request headers without redacting Authorization."""
    payload = {"path": path, "headers": dict(headers)}
    return json.dumps(payload, sort_keys=True)


def contains_raw_token(log_line: str, token: str) -> bool:
    return token in log_line
