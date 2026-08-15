# Root Cause Review Provenance

Human review progression is bound to a first-class `RootCauseAnalysis` row.

## Binding rules

- `POST /incidents/analyse` creates a `RootCauseAnalysis` with `current=true` and an `evidence_snapshot_hash`.
- Prior current analyses are marked `current=false`, `stale=true`, and `superseded_by_analysis_id=<new>`.
- `submit_review` requires a **current** analysis and stores:
  - `root_cause_analysis_id`
  - `root_cause_analysis_version`
  - `evidence_snapshot_hash`
  - `submitted_at`
  - `progression_valid=true`

## Progression gate

Remediation diagnosis may proceed only when:

1. Latest review decision is `approved`
2. `progression_valid` is true
3. Review `root_cause_analysis_id` and `evidence_snapshot_hash` match the **current** analysis

Implemented by `workflow_provenance_service.assert_valid_review_for_remediation`.
