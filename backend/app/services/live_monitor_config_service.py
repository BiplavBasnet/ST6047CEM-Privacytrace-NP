"""Durable control state for the Live Privacy Monitor (see docs/LIVE_CORRELATION_MODEL.md).

Previously this module held Live Monitor's running/mode/counters entirely in
a process-local dataclass guarded by a lock, so any process restart silently
reset the monitor to "stopped" with zero counts even if it had genuinely been
running. `LiveMonitorRuntimeState` (the DB row) is now the source of truth;
every read/write here goes through the database so state survives restarts.
A short-lived process-local cache (`_CACHE`) is kept only to avoid an extra
query on the hot `record_event_received` path within a single request/event,
and is always refreshed from (and flushed to) the DB row.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.live_monitor_runtime_state import DEFAULT_STATE_KEY, LiveMonitorRuntimeState


@dataclass
class LiveMonitorState:
    """Read-only snapshot of `LiveMonitorRuntimeState`, kept as the module's public contract."""

    running: bool = False
    mode: str = "http_ingestion"
    source_name: str | None = None
    environment: str | None = "demo"
    safe_mode: bool = True
    safety_status: str = "safe"
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    last_event_received_at: datetime | None = None
    last_alert_created_at: datetime | None = None
    event_count: int = 0
    alert_count: int = 0
    session_id: str | None = None


_CACHE_LOCK = RLock()
_CACHE: LiveMonitorState = LiveMonitorState()


def _to_dataclass(row: LiveMonitorRuntimeState) -> LiveMonitorState:
    return LiveMonitorState(
        running=row.running,
        mode=row.mode,
        source_name=row.source_name,
        environment=row.environment,
        safe_mode=row.safe_mode,
        safety_status=row.safety_status,
        started_at=row.started_at,
        stopped_at=row.stopped_at,
        last_event_received_at=row.last_event_received_at,
        last_alert_created_at=row.last_alert_created_at,
        event_count=row.event_count,
        alert_count=row.alert_count,
        session_id=row.session_id,
    )


def _get_or_create_row(db: Session, *, state_key: str = DEFAULT_STATE_KEY) -> LiveMonitorRuntimeState:
    row = db.scalar(
        select(LiveMonitorRuntimeState).where(LiveMonitorRuntimeState.state_key == state_key)
    )
    if row is None:
        row = LiveMonitorRuntimeState(state_key=state_key)
        db.add(row)
        db.flush()
    return row


def _sync_cache(state: LiveMonitorState) -> None:
    with _CACHE_LOCK:
        global _CACHE
        _CACHE = state


def get_state(db: Session, *, state_key: str = DEFAULT_STATE_KEY) -> LiveMonitorState:
    row = _get_or_create_row(db, state_key=state_key)
    state = _to_dataclass(row)
    _sync_cache(state)
    return state


def start_monitor(
    db: Session,
    *,
    mode: str,
    source_name: str | None,
    environment: str | None,
    safe_mode: bool,
    state_key: str = DEFAULT_STATE_KEY,
) -> LiveMonitorState:
    row = _get_or_create_row(db, state_key=state_key)
    now = datetime.now(UTC)
    row.running = True
    row.mode = mode
    row.source_name = source_name
    row.environment = environment
    row.safe_mode = safe_mode
    row.safety_status = "safe" if safe_mode else "manual_review_required"
    row.started_at = now
    row.stopped_at = None
    row.session_id = uuid.uuid4().hex[:16]
    db.add(row)
    db.flush()
    state = _to_dataclass(row)
    _sync_cache(state)
    return state


def stop_monitor(db: Session, *, state_key: str = DEFAULT_STATE_KEY) -> LiveMonitorState:
    row = _get_or_create_row(db, state_key=state_key)
    row.running = False
    row.stopped_at = datetime.now(UTC)
    db.add(row)
    db.flush()
    state = _to_dataclass(row)
    _sync_cache(state)
    return state


def record_event_received(db: Session, *, state_key: str = DEFAULT_STATE_KEY) -> None:
    row = _get_or_create_row(db, state_key=state_key)
    row.last_event_received_at = datetime.now(UTC)
    row.event_count = (row.event_count or 0) + 1
    db.add(row)
    db.flush()
    _sync_cache(_to_dataclass(row))


def record_alert_created(
    db: Session, alert_time: datetime, *, state_key: str = DEFAULT_STATE_KEY
) -> None:
    row = _get_or_create_row(db, state_key=state_key)
    row.last_alert_created_at = alert_time
    row.alert_count = (row.alert_count or 0) + 1
    db.add(row)
    db.flush()
    _sync_cache(_to_dataclass(row))


def cached_state() -> LiveMonitorState:
    """Last DB-synced snapshot, for callers that cannot easily obtain a session.

    Prefer `get_state(db)` wherever a session is available; this exists only
    for incidental, non-authoritative reads (e.g. logging) where forcing a DB
    round-trip is not worth it.
    """

    with _CACHE_LOCK:
        return _CACHE
