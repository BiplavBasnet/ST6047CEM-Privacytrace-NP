"""Allowlisted regression for gold-standard Authorization-header logging."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SYNTHETIC_TOKEN = "SYNTHETIC_TEST_TOKEN_123"
PATH = "/wallet/transfer"


def _load_logger():
    # Prefer sibling module (sandbox copy or fixtures tree).
    here = Path(__file__).resolve().parent / "request_logger.py"
    spec = importlib.util.spec_from_file_location("gold_request_logger", here)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_authorization_header_is_redacted_before_log_serialisation():
    mod = _load_logger()
    headers = {
        "Authorization": f"Bearer {SYNTHETIC_TOKEN}",
        "X-Request-Id": "req-gold-001",
        "Content-Type": "application/json",
    }
    line = mod.log_request_headers(headers, PATH)
    assert SYNTHETIC_TOKEN not in line
    assert "req-gold-001" in line
    assert PATH in line
    assert "[REDACTED]" in line or "authorization" not in line.lower()


def test_raw_token_detector_helper():
    mod = _load_logger()
    assert mod.contains_raw_token(f'Bearer {SYNTHETIC_TOKEN}', SYNTHETIC_TOKEN) is True
    assert mod.contains_raw_token('Bearer [REDACTED]', SYNTHETIC_TOKEN) is False
