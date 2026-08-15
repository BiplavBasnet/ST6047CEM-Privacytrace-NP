"""PrivacyTrace runtime connector (C1). Explicit emit; no monkey-patch.

Local `sensitive_exposure_engine.analyse` runs per outbound field before
queueing or HTTP. Failures never raise into the host app.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel

from privacytrace_runtime.schemas import (
    ConnectorEventData,
    ConnectorEventEnvelope,
    ConnectorEventType,
)
from privacytrace_runtime.services.sensitive_exposure_engine import analyse

VERSION = "1"
_QUEUE_MAX = 100
_TIMEOUT_S = 5
_SAFE_SUMMARY = "Runtime exposure detected; raw value withheld."
_REJECT = {"unsafe_exposure", "uncertain"}
_TRANSFORMABLE = {"message_summary"}
ReceiverStatus = Literal["UNKNOWN", "AVAILABLE", "UNAVAILABLE"]


def _now() -> datetime:
    return datetime.now(UTC)


def _unsafe_findings(text: str, *, service: str | None, endpoint: str | None, environment: str | None) -> list[dict[str, Any]]:
    findings = analyse(
        source_type="runtime_log",
        text=text,
        service=service,
        endpoint=endpoint,
        environment=environment,
    )
    return [
        f
        for f in findings
        if f.get("exposure_decision") in _REJECT or f.get("safety_status") == "unsafe"
    ]


def sanitize_data(
    data: ConnectorEventData, *, service: str | None = None
) -> tuple[ConnectorEventData | None, bool]:
    """Per-field local scan. Returns (safe_data, is_exposure) or (None, False) to drop.

    Identity-like fields fail closed. message_summary may be replaced with a
    safe summary plus masked_preview. Raw secrets never remain on the object.
    """
    dumped = data.model_dump(exclude_none=True)
    updates: dict[str, Any] = {}
    is_exposure = False
    ctx_service = service or data.service
    for key, value in dumped.items():
        if not isinstance(value, str):
            continue
        unsafe = _unsafe_findings(
            value,
            service=ctx_service,
            endpoint=data.route_template,
            environment=data.environment,
        )
        if not unsafe:
            continue
        preview = unsafe[0].get("masked_preview")
        if key in _TRANSFORMABLE and isinstance(preview, str) and preview and preview != value:
            updates["message_summary"] = _SAFE_SUMMARY
            updates["masked_value"] = preview
            updates["sensitive_type"] = unsafe[0].get("sensitive_type") or data.sensitive_type
            is_exposure = True
            continue
        return None, False
    if not updates:
        return data, False
    return data.model_copy(update=updates), is_exposure


class RuntimeConnector:
    def __init__(
        self,
        endpoint: str,
        token: str,
        source: str,
        *,
        queue_max: int = _QUEUE_MAX,
        timeout_s: float = _TIMEOUT_S,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self._token = token
        self.source = source
        self.timeout_s = timeout_s
        self._queue: deque[dict[str, Any]] = deque(maxlen=max(1, queue_max))
        self._dropped = 0
        self._last_success: datetime | None = None
        self._last_failure_reason: str | None = None
        self._receiver_status: ReceiverStatus = "UNKNOWN"

    def health(self) -> dict[str, Any]:
        return {
            "available": self._receiver_status,
            "last_success": self._last_success.isoformat() if self._last_success else None,
            "last_failure_reason": self._last_failure_reason,
            "queued": len(self._queue),
            "dropped": self._dropped,
            "version": VERSION,
        }

    def emit(
        self,
        *,
        data: ConnectorEventData | dict[str, Any],
        event_id: str | None = None,
        event_type: ConnectorEventType | None = None,
        time: datetime | None = None,
    ) -> bool:
        """Build a SAFE event and POST it. Returns True on accept/duplicate. Never raises."""
        try:
            if isinstance(data, ConnectorEventData):
                payload = data
            elif isinstance(data, BaseModel):
                payload = ConnectorEventData.model_validate(data.model_dump())
            else:
                payload = ConnectorEventData.model_validate(data)
            safe, is_exposure = sanitize_data(payload)
            if safe is None:
                self._dropped += 1
                self._last_failure_reason = "privacy_drop"
                return False
            envelope = ConnectorEventEnvelope(
                specversion="1.0",
                id=event_id or uuid.uuid4().hex,
                source=self.source,
                type=event_type
                or (
                    ConnectorEventType.RUNTIME_EXPOSURE
                    if is_exposure
                    else ConnectorEventType.RUNTIME_EVENT
                ),
                time=time or _now(),
                datacontenttype="application/json",
                data=safe,
            )
            body = envelope.model_dump(mode="json")
            if self._post(body):
                return True
            self._enqueue(body)
            return False
        except Exception:
            self._dropped += 1
            self._last_failure_reason = "emit_error"
            return False

    def flush(self) -> int:
        sent = 0
        pending = list(self._queue)
        self._queue.clear()
        for body in pending:
            if self._post(body):
                sent += 1
            else:
                self._enqueue(body)
        return sent

    def _enqueue(self, body: dict[str, Any]) -> None:
        if len(self._queue) == self._queue.maxlen:
            self._dropped += 1
            self._last_failure_reason = "queue_full"
        self._queue.append(body)

    def _post(self, body: dict[str, Any]) -> bool:
        raw = json.dumps(body).encode("utf-8")
        request = Request(
            self.endpoint,
            data=raw,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_s) as response:
                if 200 <= response.status < 300:
                    self._last_success = _now()
                    self._last_failure_reason = None
                    self._receiver_status = "AVAILABLE"
                    return True
                self._last_failure_reason = f"http_{response.status}"
                self._receiver_status = "UNAVAILABLE"
                return False
        except HTTPError as exc:
            if exc.code == 422:
                self._last_failure_reason = "rejected"
                self._dropped += 1
                self._receiver_status = "AVAILABLE"
                return False
            self._last_failure_reason = f"http_{exc.code}"
            if exc.code >= 500:
                self._receiver_status = "UNAVAILABLE"
            elif exc.code in {401, 403, 404, 409}:
                self._receiver_status = "AVAILABLE"
            else:
                self._receiver_status = "UNAVAILABLE"
            return False
        except URLError:
            self._last_failure_reason = "transport_error"
            self._receiver_status = "UNAVAILABLE"
            return False
        except TimeoutError:
            self._last_failure_reason = "timeout"
            self._receiver_status = "UNAVAILABLE"
            return False


class PrivacyTraceLogHandler(logging.Handler):
    """Optional logging handler. Calls emit(); does not monkey-patch logging."""

    def __init__(self, connector: RuntimeConnector, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.connector = connector

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.connector.emit(
                data=ConnectorEventData(
                    component=record.name,
                    severity=record.levelname.lower(),
                    message_summary=self.format(record)[:500],
                )
            )
        except Exception:
            self.handleError(record)
