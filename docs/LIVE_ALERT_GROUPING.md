# Live Alert Grouping

**Phase:** I (core engine hardening, see `docs/CORE_ENGINE_BASELINE_AUDIT.md`
§12 "Implementation order")
**Module:** `app/services/live_alert_grouping_service.py`
**Migration:** `021_unified_exposure_engine` (adds grouping columns to `privacy_alerts`)

## Problem this replaces

Before this phase, every accepted Live Monitor event created a brand-new
`PrivacyAlert` row, with no concept of "this is the same exposure happening
again." The API's `LiveAlertRead.first_seen` / `last_seen` / `repeat_count`
were synthesised at read time from a single alert's own `alert_time` (`first_
seen = last_seen = alert_time`, `repeat_count = 1`, always), regardless of
how many times the underlying exposure had actually recurred. There was no
way to answer "how long has this been happening?" or "how many times has
this repeated?" from the API.

## What grouping means here

Two Live Monitor findings are considered "the same underlying exposure
recurring" only if they share **all** of:

- `sensitive_type` (the unified exposure engine's canonical taxonomy type,
  e.g. `phone_number`, not the legacy pattern id)
- `exposure_location` (e.g. `application_log`)
- `service` (`service_name` or, if absent, `source_name`)
- `endpoint`
- `environment`

This is deliberately narrow. It does not group by raw value (raw values are
never available outside the request that produced them — see
`docs/SENSITIVE_FINGERPRINTING_MODEL.md`/`docs/UNIFIED_EXPOSURE_DETECTION_
ENGINE.md`) and it does not group across services or endpoints, even for the
same sensitive type. A phone number leaking from `wallet-service
/wallet/transfer` and the same phone number leaking from `auth-service
/auth/login` are two separate alert lineages, not one — they are different
exposure sites even if the eventual fix and remediation owner might overlap.

## Group key

`compute_group_key(sensitive_type, exposure_location, service, endpoint,
environment)` lowercases and joins the five dimensions (each defaulting to
the literal string `"unknown"` when absent) and returns
`f"AGRP-{sha256(...)[:32]}"`. This is a **grouping key derived from
non-sensitive dimensions**, not a value fingerprint — it never depends on the
raw sensitive value or its HMAC fingerprint, so it is stable and safe to
store and index in plain text (`privacy_alerts.alert_group_key`, indexed).

## Lifecycle

For each actionable finding (`exposure_decision` in `unsafe_exposure` /
`uncertain`) during `live_monitor_service.process_event`:

1. Compute the finding's group key.
2. `find_open_alert(db, group_key, at=event_time, window_seconds=...)` looks
   for the most recent alert with that group key whose `last_seen` is within
   `DEFAULT_GROUPING_WINDOW_SECONDS` (24 hours) of the event, and whose
   `status` is not `dismissed_false_positive`.
3. If found, `register_recurrence(alert, event_time=..., ...)` mutates the
   existing alert in place:
   - `first_seen` is set once (from the alert's original `alert_time`) and
     never changes afterwards.
   - `last_seen` advances to the new event's time if it is more recent.
   - `repeat_count` and `affected_trace_count` increment by 1.
   - `sensitive_types` / `masked_values` / `alert_findings` are merged
     (deduplicated by sensitive type), not replaced.
   - `confidence_score` is raised (never lowered) if the new finding's
     confidence exceeds what is already recorded, alongside its
     `confidence_level`.
   - `grouping_rule_version` is stamped with the current
     `GROUPING_RULE_VERSION` (`live_alert_grouping_v1`) so a future change to
     the grouping dimensions/window can be told apart from alerts grouped
     under an older rule.
4. If no open alert is found (first occurrence, window expired, or the prior
   alert in that group was dismissed), a new `PrivacyAlert` is created with
   `first_seen = last_seen = alert_time`, `repeat_count = 1`,
   `affected_trace_count = 1`.

## Dismissed alerts are closed lineages

An alert with `status == "dismissed_false_positive"` is excluded from
`find_open_alert`, even if it is otherwise within the grouping window. A
recurrence of the same exposure after a dismissal starts a **new** alert
lineage rather than silently reopening the analyst's dismissal decision. This
means a real, ongoing exposure that was incorrectly dismissed once will
surface again as a fresh alert on its next occurrence, instead of being
permanently suppressed.

## API surface

`LiveAlertRead` (`app/schemas/live_monitor_schema.py`) now serialises the
real, persisted `first_seen`, `last_seen`, `repeat_count`,
`affected_trace_count`, `alert_group_key`, `grouping_rule_version`,
`exposure_location`, `confidence_score`, and `confidence_level` columns
directly from `PrivacyAlert`, rather than deriving placeholder values.

## Known limitations

- The grouping window (24 hours) is a fixed, pragmatic default — not derived
  from any incident-duration model. A recurrence more than 24 hours after
  the last occurrence in the same group starts a new alert lineage even
  though it may be the "same" underlying misconfiguration.
- Grouping is exact-match on five string dimensions; it does not do fuzzy or
  semantic matching (e.g. `/wallet/transfer` and `/wallet/transfer/` are
  different endpoints, `wallet-service` and `wallet-service-v2` are different
  services).
- `find_open_alert` looks at only the single most recent matching alert
  (`ORDER BY last_seen DESC LIMIT 1`); it does not consider multiple
  concurrently-open lineages for the same group key (in normal operation
  there should only ever be one open lineage per group at a time, since new
  occurrences always attach to the most recent one).
- Grouping does not imply or claim a single root cause; it only says these
  Live Monitor observations share the same type/location/service/endpoint/
  environment signature. Root-cause determination remains a separate,
  human-reviewed step (see `docs/ROOT_CAUSE_EVIDENCE_MODEL.md`).
