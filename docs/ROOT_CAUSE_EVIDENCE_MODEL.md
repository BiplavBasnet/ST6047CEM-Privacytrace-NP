# Root-Cause Evidence Model (Phase L)

## Structured exposure facts
`backend/app/services/root_cause_exposure_facts_service.py` converts
already-persisted, safe (no-raw-value) exposure evidence into a small,
uniform `ExposureFact` shape used by the causality engine:

```
sensitive_type, exposure_location, field_name, service, endpoint,
environment, confidence, exposure_decision, deployment_version, trace_id,
event_time
```

No raw sensitive value is ever read or stored by this service — only fields
already present on masked/aggregated rows (`PrivacyAlert.alert_findings`,
`Detection` + its `NormalizedEvent`, or a raw
`sensitive_exposure_engine.analyse()` finding dict).

### Sources
| Source | Builder | Notes |
|---|---|---|
| `PrivacyAlert.alert_findings` | `facts_from_alert(alert)` | One fact per finding dict in the alert's safe JSON snapshot. |
| `Detection` (+ `NormalizedEvent`) | `fact_from_detection(detection, event)` | Exposure location is inferred from the event's `source_type` via `sensitive_exposure_engine.source_type_to_exposure_location`; deployment/trace come from the event when present. |
| Raw engine finding dict | `fact_from_finding(finding, evidence_id=...)` | For callers that already hold a `sensitive_exposure_engine.analyse()` result in memory. |

`build_exposure_facts_from_records(...)` is a pure aggregation function (no
database access) so it — and the three builders above — can be unit-tested
with plain mock objects (`SimpleNamespace`); see
`app/tests/test_root_cause_exposure_facts.py`.
`build_exposure_facts(db, incident_id)` is the thin DB-fetching wrapper that
`causality_engine.build_evidence_context` calls.

## How facts feed causality scoring
`EvidenceContext.exposure_facts` (a list of `ExposureFact.as_dict()` dicts) is
populated once per `build_evidence_context` call and used in two ways:

1. **First-class signal source.** A `root_cause_rules.yaml` signal can use
   `match: exposure_fact_type_at_location` with a
   `value: {sensitive_types: [...], exposure_locations: [...]}` spec. It
   matches when any exposure fact has both a matching `sensitive_type` and
   `exposure_location`. Example (`authorization_header_logging`):

   ```yaml
   - name: exposure_fact_token_at_header_location
     weight: 0.10
     match: exposure_fact_type_at_location
     value:
       sensitive_types: [bearer_token, jwt_token, api_key, session_token]
       exposure_locations: [request_header_log, request_header_processing]
   ```

2. **Ontology category boost.** See `docs/ROOT_CAUSE_ONTOLOGY.md` — the same
   `ctx.exposure_facts` list is checked against ontology categories mapped to
   the candidate's `likely_root_cause`.

Both paths only ever *add* a transparent, bounded amount to the base score,
and both record exactly which signal/category fired and why in
`score_breakdown` / `matched_signals`.

## Evidence strength: causal vs. post-remediation (Phase M)
`backend/app/services/root_cause_evidence_strength_service.py` deliberately
splits what used to be one mixed "evidence strength" concept into two
independently-computed results, enforced structurally by two separate input
dataclasses:

### `CausalEvidenceInputs` → `compute_causal_evidence_strength_from_context`
Fields: `incident`, `alerts`, `detections`, `evidence_files`, `events`,
`scanners`, `cicd`, `deployments`, `sast_count`, `top_root_cause`.

This dataclass has **no field** for remediation actions, review decisions, or
fix verification — it is structurally impossible for this function to read
that state, not just documented as forbidden. It scores purely on:
- symptom evidence (alerts, detections, log/SIEM evidence files),
- timeline correlation (alert/event/CI-CD/deployment timestamps),
- technical evidence (deployment, configuration, changed-file, scan, or
  scanner-record correlation),
- contradicting evidence recorded on the top-ranked `RootCauseScore`.

Output includes `causal_strength_level` (`weak`/`medium`/`strong`/
`very_strong`), `causal_strength_score`, `causal_confidence_level`/`score`,
a confidence cap + reason, supporting/contradicting evidence, and
`excludes_post_remediation_evidence: true` as an explicit marker.

### `ValidationInputs` → `compute_post_remediation_validation_from_context`
Fields: `incident`, `remediation_actions`, `review`, `verification`,
`events`, `evidence_files`, `cicd`, `top_root_cause`.

This is the *only* place remediation/retest/verification/review state is
read. Output includes `validation_status` (`not_started` →
`remediation_recorded` → `retested` → `verified_passed`/`verified_failed`),
`validation_score`, `remediation_matches_cause`, `retest_matches_cause`,
`verification_passed`/`failed`, and `review_approved`.

### Combined entry point
`calculate_evidence_strength(db, incident_id)` (used by existing routers and
`final_report_service`) computes both and returns:

- Top-level `confidence_level`/`confidence_score`/`evidence_strength_*`
  fields sourced **only** from the causal result — a later successful fix
  can never retroactively inflate (and a failed one can never deflate) the
  historical record of what the pre-remediation evidence looked like.
- `causal_evidence_strength`: the full causal result, nested.
- `post_remediation_validation`: the full validation result, nested.

`app/tests/test_root_cause_causal_vs_validation.py` asserts this contract
directly: identical `CausalEvidenceInputs` always produce an identical
causal score no matter what `ValidationInputs` are computed alongside it.

## Safety wording
`_safe_text` / `FORBIDDEN_REPLACEMENTS` rewrite phrases like "proven root
cause" or "confirmed cause" to "likely cause" / "likely contribution" before
any string reaches a response. All root-cause and evidence-strength output
uses "likely", "supports", "correlates with" — never "proved caused by" or
"confirmed".
