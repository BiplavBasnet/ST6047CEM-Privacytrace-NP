"""Minimal file-tail forwarder for the PrivacyTrace-NP Integration Gateway."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required configuration: {name}")
    return value


def _enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


BASE_URL = _required("PRIVACYTRACE_URL").rstrip("/")
TOKEN = _required("PRIVACYTRACE_TOKEN")
LOG_FILE = Path(_required("LOG_FILE"))
SOURCE_NAME = _required("SOURCE_NAME")
SERVICE_NAME = os.getenv("SERVICE_NAME", SOURCE_NAME).strip() or SOURCE_NAME
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip() or "development"
POLL_INTERVAL = max(0.25, float(os.getenv("POLL_INTERVAL_SECONDS", "2")))
DRY_RUN = _enabled("DRY_RUN")
SYNTHETIC_TEST_MODE = _enabled("SYNTHETIC_TEST_MODE")


def _event(message: str) -> dict:
    return {
        "source_name": SOURCE_NAME,
        "source_type": "application_log",
        "source_format": "generic_json",
        "environment": ENVIRONMENT,
        "service_name": SERVICE_NAME,
        "message": message,
        "metadata": {"forwarder": "privacytrace-file-tail"},
    }


def _send(message: str) -> None:
    body = json.dumps(_event(message)).encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()[:12]
    if DRY_RUN:
        print(f"dry-run event prepared bytes={len(body)} hash_prefix={digest}")
        return
    request = urllib.request.Request(
        f"{BASE_URL}/integrations/events",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            print(f"event delivered status={response.status} hash_prefix={digest}")
    except urllib.error.HTTPError as exc:
        print(f"gateway rejected event status={exc.code} hash_prefix={digest}")
    except (urllib.error.URLError, TimeoutError):
        print(f"gateway unavailable hash_prefix={digest}")


def _run_synthetic() -> None:
    phone = "984" + "1234" + "567"
    _send(f"Synthetic forwarder check phone={phone}")


def _follow_file() -> None:
    while not LOG_FILE.exists():
        print("configured log file is not available; retrying")
        time.sleep(POLL_INTERVAL)
    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, os.SEEK_END)
        print("log forwarder started")
        while True:
            line = handle.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue
            message = line.rstrip("\r\n")
            if message:
                _send(message)


if __name__ == "__main__":
    if SYNTHETIC_TEST_MODE:
        _run_synthetic()
    else:
        _follow_file()
