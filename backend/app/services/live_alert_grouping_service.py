"""Real alert grouping for the Live Privacy Monitor.

Historically every accepted Live Monitor event created a brand-new
`PrivacyAlert` row, and `LiveAlertRead.first_seen`/`last_seen`/`repeat_count`
were hardcoded to `alert_time`/`alert_time`/`1` (see
`app/services/live_alert_service.alert_to_read`, pre-Phase-I). That made
"how long has this been happening" and "how many times has this repeated"
unanswerable from the API.

This module computes a deterministic `alert_group_key` from the dimensions
that identify "the same underlying exposure" — sensitive type, exposure
location, service, endpoint, and environment — and looks up an existing open
alert in that group within a recency window before deciding whether to
create a new alert or record another occurrence on the existing one. See
`docs/LIVE_ALERT_GROUPING.md` for the full model and its limitations.

`affected_trace_count` is the distinct count of known `trace_id` values
recorded via `AlertTraceReference` — never incremented blindly, and never
fabricated when no trace_id is present.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.privacy_alert import PrivacyAlert
from app.models.workflow_verification import AlertTraceReference
from app.services import correlation_fingerprint_service

GROUPING_RULE_VERSION = "live_alert_grouping_v1"

# How long a group stays "open" for new occurrences to attach to before a
# fresh event with the same key starts a new alert lineage instead. This is a
# pragmatic default, not a claim about incident duration.
DEFAULT_GROUPING_WINDOW_SECONDS = 24 * 60 * 60

_CLOSED_STATUSES = {"dismissed_false_positive"}


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def acquire_group_claim(db: Session, group_key: str) -> None:
    """Serialize same-group create/attach, including the no-row-yet case."""

    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    unsigned = int.from_bytes(hashlib.sha256(group_key.encode()).digest()[:8], "big")
    lock_key = unsigned if unsigned < 2**63 else unsigned - 2**64
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})


def compute_group_key(
    *,
    sensitive_type: str | None,
    exposure_location: str | None,
    service: str | None,
    endpoint: str | None,
    environment: str | None,
) -> str:
    """Deterministic group key for "the same underlying exposure recurring".

    Two events group together only if they share sensitive type, exposure
    location, service, endpoint, and environment — deliberately narrow so
    unrelated services/endpoints never merge into one alert.
    """

    parts = [
        str(sensitive_type or "unknown").strip().casefold(),
        str(exposure_location or "unknown").strip().casefold(),
        str(service or "unknown").strip().casefold(),
        str(endpoint or "unknown").strip().casefold(),
        str(environment or "unknown").strip().casefold(),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"AGRP-{digest[:32]}"


def find_open_alert(
    db: Session,
    group_key: str,
    *,
    at: datetime | None = None,
    window_seconds: int = DEFAULT_GROUPING_WINDOW_SECONDS,
    for_update: bool = True,
) -> PrivacyAlert | None:
    """Return the most recent still-open alert for `group_key`, if any.

    "Open" means: not dismissed as a false positive, and last seen within
    `window_seconds` of `at`. Alerts already linked to an incident remain
    groupable — a recurring exposure on an already-investigated incident is
    still useful signal, and stays reflected on the same alert lineage.

    Uses SELECT FOR UPDATE when `for_update` so concurrent ingest of the same
    group key serialises on the existing row (minimal concurrency safety).
    Simultaneous first-create races still resolve by re-checking after flush;
    see `claim_or_attach` in `live_monitor_service` callers.
    """

    if not group_key:
        return None
    reference_time = at or datetime.now(UTC)
    cutoff = reference_time - timedelta(seconds=window_seconds)
    stmt = (
        select(PrivacyAlert)
        .where(PrivacyAlert.alert_group_key == group_key)
        .where(PrivacyAlert.last_seen.is_not(None))
        .where(PrivacyAlert.last_seen >= cutoff)
        .order_by(PrivacyAlert.last_seen.desc())
        .limit(1)
    )
    if for_update:
        stmt = stmt.with_for_update()
    candidate = db.scalar(stmt)
    if candidate is None or candidate.status in _CLOSED_STATUSES:
        return None
    return candidate


def _distinct_trace_count(db: Session, alert_id: str) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(AlertTraceReference)
            .where(
                AlertTraceReference.alert_id == alert_id,
                AlertTraceReference.fingerprint_method == "hmac_sha256_v1",
                AlertTraceReference.fingerprint_version == "v1",
            )
        )
        or 0
    )


def record_trace_reference(
    db: Session,
    alert: PrivacyAlert,
    *,
    trace_fingerprint: str | None = None,
    trace_id: str | None = None,
    at: datetime | None = None,
) -> PrivacyAlert:
    """Upsert a known trace fingerprint; set affected_trace_count = distinct.

    No trace_id → count stays based on already-known traces only (honest 0
    if none). Never fabricates a synthetic trace.
    """

    if trace_fingerprint is None and trace_id:
        item = correlation_fingerprint_service.fingerprint(trace_id, "trace_id")
        trace_fingerprint = item["fingerprint"] if item else None
    if not trace_fingerprint:
        count = _distinct_trace_count(db, alert.alert_id)
        alert.affected_trace_count = count or None
        alert.trace_count_quality = "exact" if count else "unavailable"
        return alert

    fingerprint = str(trace_fingerprint).strip()[:128]
    if not fingerprint:
        alert.affected_trace_count = None
        alert.trace_count_quality = "unavailable"
        return alert

    now = at or datetime.now(UTC)
    existing = db.scalar(
        select(AlertTraceReference).where(
            AlertTraceReference.alert_id == alert.alert_id,
            AlertTraceReference.trace_fingerprint == fingerprint,
        )
    )
    if existing is None:
        try:
            with db.begin_nested():
                db.add(
                    AlertTraceReference(
                        alert_id=alert.alert_id,
                        trace_fingerprint=fingerprint,
                        fingerprint_method="hmac_sha256_v1",
                        fingerprint_version="v1",
                        first_seen=now,
                        last_seen=now,
                    )
                )
                db.flush()
        except IntegrityError:
            existing = db.scalar(
                select(AlertTraceReference).where(
                    AlertTraceReference.alert_id == alert.alert_id,
                    AlertTraceReference.trace_fingerprint == fingerprint,
                )
            )
            if existing is not None:
                if _utc(now) > _utc(existing.last_seen):
                    existing.last_seen = now
                db.add(existing)
    else:
        if _utc(now) > _utc(existing.last_seen):
            existing.last_seen = now
        db.add(existing)
    db.flush()
    alert.affected_trace_count = _distinct_trace_count(db, alert.alert_id)
    alert.trace_count_quality = "exact"
    return alert


def register_recurrence(
    db: Session,
    alert: PrivacyAlert,
    *,
    observed_at: datetime | None = None,
    event_time: datetime | None = None,
    source_event_time: datetime | None = None,
    source_time_quality: str = "inferred",
    source_time_inferred: bool = True,
    source_timezone_name: str | None = None,
    sensitive_types: list[str] | None = None,
    masked_values: list[str] | None = None,
    confidence_score: float | None = None,
    confidence_level: str | None = None,
    alert_findings: list[dict[str, Any]] | None = None,
    trace_fingerprint: str | None = None,
) -> PrivacyAlert:
    """Mutate `alert` in place to reflect one more occurrence of its group."""

    observed_at = observed_at or event_time or datetime.now(UTC)
    if alert.first_seen is None:
        alert.first_seen = alert.alert_time
    if alert.last_seen is None or _utc(observed_at) >= _utc(alert.last_seen):
        alert.last_seen = observed_at
    if source_event_time is not None:
        alert.source_time_quality = source_time_quality
        alert.source_time_inferred = source_time_inferred
        alert.source_timezone_name = source_timezone_name
        if alert.first_source_event_time is None or _utc(source_event_time) < _utc(alert.first_source_event_time):
            alert.first_source_event_time = source_event_time
        if alert.last_source_event_time is None or _utc(source_event_time) > _utc(alert.last_source_event_time):
            alert.last_source_event_time = source_event_time
    alert.repeat_count = (alert.repeat_count or 1) + 1
    alert.grouping_rule_version = GROUPING_RULE_VERSION
    record_trace_reference(db, alert, trace_fingerprint=trace_fingerprint, at=observed_at)

    if sensitive_types:
        alert.sensitive_types = list(
            dict.fromkeys(list(alert.sensitive_types or []) + list(sensitive_types))
        )
    if masked_values:
        alert.masked_values = list(
            dict.fromkeys(list(alert.masked_values or []) + list(masked_values))
        )
    if confidence_score is not None and (
        alert.confidence_score is None or confidence_score > alert.confidence_score
    ):
        alert.confidence_score = confidence_score
        alert.confidence_level = confidence_level
    if alert_findings:
        merged: dict[str, dict[str, Any]] = {
            str(item.get("sensitive_type")): item for item in (alert.alert_findings or [])
        }
        for item in alert_findings:
            merged[str(item.get("sensitive_type"))] = item
        alert.alert_findings = list(merged.values())
    return alert
