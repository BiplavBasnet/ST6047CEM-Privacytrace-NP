# Live/Integration Correlation Model

**Modules:** `app/services/siem_import_service.py` (`_metadata_advice`,
correlation-key extraction), `app/services/cicd_evidence_service.py`
(`correlate_evidence`), `app/services/scanner_correlation_service.py`
(`correlate_incident`)

This document covers how PrivacyTrace links a Live Monitor / Universal
Integration Gateway event, a CI/CD evidence record, or a scanner finding back
to the rest of an incident's evidence. It is a **separate concern** from
`docs/LIVE_ALERT_GROUPING.md` (which decides whether two *sensitive-data
exposure* observations are "the same recurring exposure") — grouping never
looks at an incident at all, while everything in this document is about
connecting evidence *to* an incident or estimating how strong that
connection is.

## Live Monitor first-class correlation fields

`LiveMonitorEventRequest` accepts first-class correlation fields, but raw
trace/request/correlation/transaction/session identifiers are transient.
Only central versioned keyed-HMAC fingerprints are stored. If the HMAC key
is unavailable, no correlatable value or unkeyed fallback is persisted.

Distinct known traces for an alert are tracked in `AlertTraceReference`
(`uq_alert_trace_fingerprint`); `PrivacyAlert.affected_trace_count` is that
distinct count — never incremented blindly, and never fabricated when
`trace_id` is absent. Legacy untrusted references are retained as history
but excluded from trustworthy counts.

Grouping admission uses server ingestion time, so delayed or future source
timestamps cannot keep a group open. UTC-normalised source event time is
preserved separately with quality/inferred/timezone metadata. PostgreSQL
transaction advisory claims serialize concurrent first creation.

## 1. Correlation keys extracted at ingestion time (`siem_import_service.py`)

Every event ingested through the Universal Integration Gateway or a SIEM
import is scanned (via `_metadata_advice`) for a fixed set of well-known
metadata fields that support later correlation, regardless of source
vendor's naming convention. `_find_nested` looks for any of a field's known
aliases inside the request's `metadata`/`payload`:

| Correlation key | Aliases checked | Used for |
|---|---|---|
| `deployment_version` | `deployment_version`, `release_version`, `version` | Matching an event to a specific release for `docs/DATABASE_MIGRATION_STRATEGY.md`-adjacent CI/CD correlation (see §2). |
| `trace_id` | `trace_id`, `trace.id` (or `canonical["trace_id"]` if the caller set it directly) | HMAC equality for timeline reconstruction across services. |
| `request_id` | `request_id`, `req_id` | Same, at per-request granularity. |
| `correlation_id` | `correlation_id`, `correlation.id` | Vendor-supplied explicit correlation identifier. |
| `transaction_reference` (stored hashed) | `transaction_reference`, `transaction_ref`, `transaction_id` | Correlating financial-domain events without persisting the raw reference. |
| `session_reference` (stored hashed) | `session_id`, `session_reference` | Correlating events within one user session without persisting the raw session ID. |
| `commit_reference` | `commit_sha`, `commit_reference`, `commit_hash`, `git_commit` | Linking an event to the code change that likely caused it. |
| `configuration_version` | `configuration_version`, `config_version` | Same, for a config-driven deployment. |
| `host_reference` | `host`, `hostname`, `host_reference`, `instance_id` | Narrowing which instance/host produced an event. |

Every scalar value placed into the stored `correlation_keys` JSONB column is
passed through `_safe_scalar()` first — masked via
`live_monitor_safety_service.scan_and_mask_text` and rejected (`None`) rather
than stored if unsafe, and truncated to 512 characters. `transaction_
reference` and `session_reference` are stored **only as a hash**
(`_hash_value`), never as the raw identifier, since they can be
directly-identifying financial/session data even though they are not one of
the engine's regex-detected "sensitive value" types per se.

### Correlation strength (`evidence_strength`)

```
core_complete   = service_name AND endpoint AND event_time are all present
supporting_key  = deployment_version OR trace_id OR transaction_reference present
strength = "strong"   if core_complete AND supporting_key
           "moderate"  if core_complete (but no supporting key), OR supporting_key alone
           "weak"      otherwise
```

(See `_metadata_advice`'s full branching for the exact moderate/weak
boundary — the summary above is the practical effect.) This value is stored
as `NormalizedEvent`/`PrivacyAlert.evidence_strength` and surfaced on
`LiveAlertRead.evidence_strength`, so a reviewer can immediately see whether
an alert has enough context to be corroborated against other evidence or is
essentially an isolated, hard-to-cross-reference observation.

### Missing-metadata recommendations

Whenever a "core" field (`service_name`, `endpoint`, `event_time`) or a
useful correlation key (`deployment_version`, `trace_id`/`transaction_
reference`) is absent, `_metadata_advice` appends a specific, actionable
recommendation string (e.g. `"Add trace_id or transaction reference for
timeline reconstruction."`). These are stored/returned as `missing_metadata`
and `correlation_recommendations` on the event/alert response — this is
advice to the *source system's integrator*, not something PrivacyTrace can
fix on its own.

## 2. CI/CD evidence-to-incident correlation candidates (`cicd_evidence_service.correlate_evidence`)

Given an `incident_id`, scores every stored `CicdEvidence` row as a candidate
correlation to that incident (not a hard link — a reviewer decides whether
to actually attach it):

```
+0.35  same affected_service as the incident
+0.15  same environment as any alert already linked to the incident
+0.20  same deployment_version as any linked event evidence
+0.20  the CI/CD event happened within 7 days before the incident's first_seen
+0.10  the CI/CD change_categories overlap tokens from the incident's current
       top-ranked likely_root_cause (Phase N: current analysis version only)
score = max(score, 0.6) if the row is already manually linked to this incident
```

Every contributing rule appends a human-readable `reasons` string, and
candidates are returned sorted by score, descending. A candidate with
`score == 0` is excluded entirely (no signal at all connects it to the
incident).

## 3. Scanner-evidence-to-incident correlation (`scanner_correlation_service.correlate_incident`)

Separately, `compute_causal_relevance()` scores each `ScannerEvidenceRecord`
already linked to an incident (not candidate discovery — this scores
evidence a user has already attached) by verification status, severity,
service/endpoint name overlap with the incident, path heuristics (`test`/
`fixture`/`mock` paths score down; `auth`/`config`/`logging`/`env`/`secret`
paths score up), and bucket into `strong` (≥0.75) / `moderate` (≥0.45) /
`weak` (<0.45) supporting evidence. See `docs/CAUSAL_EVIDENCE_GRAPH.md` for
how this feeds the broader causality reasoning.

## What this correlation model does *not* claim

- **No automatic incident linking for Live Monitor alerts.** A `PrivacyAlert`
  is only attached to an incident when a human explicitly calls the
  link-to-incident action (`live_monitor_service`, setting
  `alert.linked_incident_id` and `alert.status = "linked_to_incident"`).
  Nothing in this document's correlation-key extraction or evidence-strength
  scoring *automatically* creates that link — it only prepares the metadata
  that would make a manual link well-justified, and (for CI/CD evidence)
  surfaces ranked *candidates* for a human to choose from.
- **Correlation is not causation.** `scanner_correlation_service`'s own
  constant (`CORRELATION_SUMMARY`) states this explicitly: "Scanner evidence
  contributes supporting evidence for investigation; it does not prove root
  cause. Human review is required." The same caveat applies to every score
  in this document.
- **No cross-incident correlation.** Every scoring function here operates
  within one incident's scope; there is no mechanism that says "these two
  separate incidents are probably related."

## Known limitations

- The CI/CD candidate score, scanner causal-relevance score, and evidence-
  strength classification are all fixed constants tuned by inspection, like
  the exposure confidence model — see `docs/DETECTION_CONFIDENCE_MODEL.md`'s
  same caveat, which applies here too: none of these are calibrated
  probabilities.
- `transaction_reference`/`session_reference` correlation is hash-based
  equality only; there is no fuzzy matching (e.g. a reference with a
  different casing or a stray leading zero produces a different hash and
  will not correlate).
- The 7-day CI/CD lookback window (like the 24-hour alert-grouping window in
  `docs/LIVE_ALERT_GROUPING.md`) is a fixed pragmatic default, not derived
  from a measured incident-latency distribution.
- There is no automated "correlate this Live Monitor alert against other
  open alerts/incidents" recommendation surface today — only the CI/CD and
  scanner-evidence correlation described above; extending equivalent
  candidate-ranking to Live Monitor alerts themselves is listed as future
  work in `docs/LIMITATIONS_AND_FUTURE_WORK.md`.
