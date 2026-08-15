# Root-Cause Analysis Versioning & Staleness (Phase N)

## Why
Before Phase N, re-running `analyse_incident` deleted the previous
`root_cause_scores` rows and wrote fresh ones, so there was no way to tell
that a ranking had changed, when, or why, and no way to know a *displayed*
ranking was already outdated because new evidence had been linked since it
was computed. Phase N adds versioning and staleness without ever deleting or
mutating a prior analysis's scoring fields.

## New `RootCauseScore` fields
Added by `backend/alembic/versions/022_root_cause_versioning.py` (guarded
with `has_column` checks, safe to run against a database bootstrapped either
by migration `001` or by `Base.metadata.create_all`):

| Field | Meaning |
|---|---|
| `analysis_id` | Groups every `RootCauseScore` row produced by one `analyse_incident` run. Format: `RCA-ANALYSIS-<hex>`. |
| `analysis_version` | Sequential integer per incident, starting at 1. |
| `rules_version` | Fingerprint of the `root_cause_rules.yaml` + ontology in effect when this analysis ran (`compute_rules_version`). Informational — shows an old analysis used different rules; it does not by itself mark anything stale. |
| `evidence_snapshot_hash` | Deterministic hash of the detections/events/evidence/scanner/remediation/exposure-fact ids the analysis was based on (`compute_evidence_snapshot_hash`). |
| `analysed_at` | Timestamp the analysis was persisted. |
| `stale` | `True` once relevant new evidence has been linked since this row's `analysis_id` ran. |
| `stale_reason` | Human-readable reason the row was marked stale. |
| `superseded_by_analysis_id` | Set on every row of a batch once a *newer* `analyse_incident` run has completed; `None` for the current batch. |

Existing rows are backfilled with `analysis_id = 'RCA-ANALYSIS-LEGACY-' ||
incident_id`, `analysis_version = 1`, and `analysed_at = created_at`.

## Re-analysis never destroys history
`causality_engine.analyse_incident(db, incident_id, force=True)`:

1. Loads all existing `RootCauseScore` rows for the incident.
2. Mints a new `analysis_id` and the next `analysis_version`
   (`next_analysis_version`).
3. Marks the previous batch's rows `superseded_by_analysis_id = <new id>` and
   `stale = True` (`supersede_rows`) — it does **not** delete or edit their
   scoring fields.
4. Persists the newly ranked causes as a fresh batch tagged with the new
   `analysis_id`/`analysis_version`/`rules_version`/`evidence_snapshot_hash`.

Without `force=True`, `analyse_incident` is a no-op if any analysis already
exists (unchanged pre-Phase-N behaviour), returning the current batch's
summary with `skipped=True`.

## Reading "the" current analysis
`causality_engine.list_root_cause_scores(db, incident_id)` defaults to only
the latest `analysis_version` batch (`include_history=True` returns every
version). All other services that used to query `RootCauseScore` directly
(`ai_remediation_service`, `counterfactual_analysis_service`,
`llm_context_service`, `cicd_evidence_service`, `evaluation_metric_service`,
`final_report_service`, `root_cause_evidence_strength_service._top_root_cause`)
now go through this helper, so a superseded/stale historical row is never
mistaken for "the" current ranking.

## Marking an analysis stale
`causality_engine.mark_stale(db, incident_id, reason)` flags every row in the
incident's current batch `stale = True` with the given `reason` (idempotent —
calling it again with the same reason is a no-op). It does not commit; the
caller's existing transaction owns that.

Callers that invoke it whenever new evidence is linked to an
already-analysed incident:

| Caller | Trigger |
|---|---|
| `detection_service.detect_event` | New `Detection` rows created for the incident. |
| `live_monitor_service.create_or_link_incident` | A live privacy alert is linked to the incident. |
| `cicd_evidence_service.link_evidence` | CI/CD evidence is linked to the incident. |
| `scanner_bridge_service` (import-with-link and `link_evidence`) | Scanner evidence is imported-and-linked, or linked, to the incident. |

`stale` is surfaced to reviewers via `get_incident_trace` (`analysis_stale`,
`analysis_stale_reason`, `analysis_version` on the trace and on each ranked
cause) and via the graph disclaimer; it is never silently hidden.

## Status endpoint
`GET /incidents/{incident_id}/root-cause-status` →
`RootCauseAnalysisStatus` (`causality_engine.get_root_cause_status`):

```json
{
  "incident_id": "INC-...",
  "analysed": true,
  "analysis_id": "RCA-ANALYSIS-...",
  "analysis_version": 2,
  "rules_version": "rules:...:ontology:1.0",
  "evidence_snapshot_hash": "...",
  "analysed_at": "2026-...",
  "stale": false,
  "stale_reason": null,
  "root_cause_count": 3,
  "top_likely_cause": "unsafe_request_body_logging",
  "superseded_by_analysis_id": null
}
```

This is a lightweight read used by clients that only need to know whether to
prompt a reviewer to re-run analysis, without fetching the full trace.

## Testing without PostgreSQL
`app/tests/test_root_cause_staleness.py` exercises `apply_staleness_to_rows`,
`supersede_rows`, `next_analysis_version` directly against in-memory
`RootCauseScore` instances (never flushed to a database), and `mark_stale`
against a `unittest.mock.MagicMock` session with
`causality_engine.list_root_cause_scores` monkeypatched — so the versioning
contract is covered without a live PostgreSQL instance.
