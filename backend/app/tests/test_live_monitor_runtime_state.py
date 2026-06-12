"""Phase J: durable Live Monitor runtime state (see docs/LIVE_CORRELATION_MODEL.md).

`live_monitor_config_service` used to hold running/mode/counters only in a
process-local dataclass, so a process restart always reported the monitor as
stopped with zero counts. `LiveMonitorRuntimeState` is now the source of
truth: each test here writes state through one `SessionLocal()` session,
closes it, and reads it back through a brand-new session with no shared
identity map or cache — the same shape of read a fresh process would do
after a restart.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.database import SessionLocal
from app.services import live_monitor_config_service

pytestmark = pytest.mark.usefixtures("migrated_db")


def _unique_state_key() -> str:
    return f"test-runtime-state-{uuid.uuid4().hex[:12]}"


def test_state_survives_new_session_after_start():
    state_key = _unique_state_key()

    session_a = SessionLocal()
    try:
        live_monitor_config_service.start_monitor(
            session_a,
            mode="http_ingestion",
            source_name="pytest-source",
            environment="test",
            safe_mode=True,
            state_key=state_key,
        )
        session_a.commit()
    finally:
        session_a.close()

    session_b = SessionLocal()
    try:
        state = live_monitor_config_service.get_state(session_b, state_key=state_key)
    finally:
        session_b.close()

    assert state.running is True
    assert state.source_name == "pytest-source"
    assert state.environment == "test"
    assert state.safe_mode is True
    assert state.started_at is not None
    assert state.stopped_at is None
    assert state.session_id is not None


def test_event_and_alert_counters_persist_across_sessions():
    state_key = _unique_state_key()

    session_a = SessionLocal()
    try:
        live_monitor_config_service.start_monitor(
            session_a,
            mode="http_ingestion",
            source_name="pytest-source",
            environment="test",
            safe_mode=True,
            state_key=state_key,
        )
        session_a.commit()
    finally:
        session_a.close()

    session_b = SessionLocal()
    try:
        live_monitor_config_service.record_event_received(session_b, state_key=state_key)
        live_monitor_config_service.record_event_received(session_b, state_key=state_key)
        live_monitor_config_service.record_alert_created(
            session_b, datetime.now(UTC), state_key=state_key
        )
        session_b.commit()
    finally:
        session_b.close()

    session_c = SessionLocal()
    try:
        state = live_monitor_config_service.get_state(session_c, state_key=state_key)
    finally:
        session_c.close()

    assert state.event_count == 2
    assert state.alert_count == 1
    assert state.last_event_received_at is not None
    assert state.last_alert_created_at is not None


def test_stop_after_restart_reflects_in_new_session():
    state_key = _unique_state_key()

    session_a = SessionLocal()
    try:
        live_monitor_config_service.start_monitor(
            session_a,
            mode="http_ingestion",
            source_name="pytest-source",
            environment="test",
            safe_mode=True,
            state_key=state_key,
        )
        session_a.commit()
    finally:
        session_a.close()

    session_b = SessionLocal()
    try:
        live_monitor_config_service.stop_monitor(session_b, state_key=state_key)
        session_b.commit()
    finally:
        session_b.close()

    session_c = SessionLocal()
    try:
        state = live_monitor_config_service.get_state(session_c, state_key=state_key)
    finally:
        session_c.close()

    assert state.running is False
    assert state.stopped_at is not None
    # Counters and identifying fields are not reset just by stopping.
    assert state.source_name == "pytest-source"


def test_unknown_state_key_defaults_to_a_fresh_stopped_row():
    state_key = _unique_state_key()

    session = SessionLocal()
    try:
        state = live_monitor_config_service.get_state(session, state_key=state_key)
        session.commit()
    finally:
        session.close()

    assert state.running is False
    assert state.event_count == 0
    assert state.alert_count == 0
    assert state.started_at is None


def test_multiple_state_keys_do_not_interfere():
    key_one = _unique_state_key()
    key_two = _unique_state_key()

    session = SessionLocal()
    try:
        live_monitor_config_service.start_monitor(
            session,
            mode="http_ingestion",
            source_name="source-one",
            environment="test",
            safe_mode=True,
            state_key=key_one,
        )
        session.commit()
    finally:
        session.close()

    session = SessionLocal()
    try:
        state_one = live_monitor_config_service.get_state(session, state_key=key_one)
        state_two = live_monitor_config_service.get_state(session, state_key=key_two)
        session.commit()
    finally:
        session.close()

    assert state_one.running is True
    assert state_one.source_name == "source-one"
    assert state_two.running is False
    assert state_two.source_name is None
