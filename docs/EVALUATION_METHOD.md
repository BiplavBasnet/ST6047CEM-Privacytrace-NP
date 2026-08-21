# Evaluation Method (Phase Q)

This document describes how PrivacyTrace-NP's evaluation metrics are
computed, split into two tracks that intentionally coexist:

1. **Instance-level dataset evaluation** (new, Phase Q) — pure, offline,
   database-free scoring of `sensitive_exposure_engine.analyse()` against
   `app/evaluation_data/instance_level_cases.yaml`. See
   `docs/EVALUATION_DATASET_DESIGN.md` for the dataset itself.
2. **Scenario-based DB evaluation** (pre-existing, Phase 10, kept
   backward-compatible) — scoring of a live, seeded incident
   (`INC-SEED-001`) against `SCENARIO_GROUND_TRUTH["scenario_1"]` in
   `evaluation_metric_service.py`.

Both are implemented in `backend/app/services/`; both remain callable and
tested. Nothing in Phase Q removed or renamed the scenario-based API — see
"Backward compatibility" below.

## 1. Instance-level dataset evaluation

Entry points:
- `instance_level_evaluation_service.run_instance_level_evaluation(path=None)`
  — pure function, no DB, returns an `InstanceLevelEvaluationResult`.
- `evaluation_metric_service.run_instance_level_dataset_evaluation(db=None,
  persist=False, dataset_path=None)` — thin wrapper; if `persist=True` it
  also writes headline metrics as `EvaluationMetric` rows under
  `scenario_name="instance_level_dataset_v1"`, alongside (not replacing) the
  older `scenario_1` rows.

### Instance-level precision / recall / F1

For each dataset case, expected and predicted findings are grouped by
`sensitive_type` as **multisets** (via `collections.Counter`), not sets:

```
matched(type)          = min(expected_count(type), predicted_count(type))
true_positive(type)    = matched(type)
false_positive(type)   = predicted_count(type) - matched(type)
false_negative(type)   = expected_count(type) - matched(type)
```

Totals are summed across all types and all cases, then:

```
precision = TP / (TP + FP)   (0.0 if TP + FP == 0)
recall    = TP / (TP + FN)   (0.0 if TP + FN == 0)
f1        = 2 * precision * recall / (precision + recall)   (0.0 if both are 0)
```

The same formulas are additionally computed **per sensitive_type**
(`per_type_metrics`), so a type with weak coverage cannot hide behind a
strong aggregate score.

This directly fixes the type-set-intersection weakness described in
`docs/EVALUATION_DATASET_DESIGN.md`: `POS-PHONE-LOG-MULTI`'s two phone-number
occurrences must be matched by two predicted findings, or the case
contributes a false negative even though the type `"phone_number"` is
technically "detected."

### Unsafe-exposure classification accuracy

Every `expected_instances` item may declare an `exposure_decision`
(`unsafe_exposure`, `already_safely_masked`, `legitimate_processing`, ...).
For each such item, the evaluator looks for *any* engine finding of the same
`sensitive_type` whose `exposure_decision` matches exactly:

```
accuracy = decisions_matched / decisions_checked
```

This is deliberately a **separate** metric from precision/recall — a case
can count as a "true positive" for type-level counting purposes while still
failing the classification-accuracy check if the engine found the right
type but assigned the wrong exposure decision (e.g. calling a legitimate
in-flight header value `unsafe_exposure`).

### Masking success / raw leakage

For every case that declares a `raw_value`/`raw_values`, the evaluator
serialises the engine's full finding output (`json.dumps(findings)`) and
checks two things: the literal raw string must not appear anywhere in that
blob, and `audit_safety_service.scan_text_for_sensitive()` must not flag the
blob either (a second, independent check in case the raw value appears in a
different but still-recognisable form). A case fails ("leaked") if either
check trips.

```
masking_success_rate            = (checked_cases - leaked_cases) / checked_cases   (1.0 if no case declares a raw value)
raw_sensitive_value_leak_count  = leaked_cases   (must be 0 for a clean run)
```

### What this track does not measure

- It does not touch the database, an incident, or any persisted
  `Detection`/`RootCauseScore` row — it is a pure function over the YAML
  dataset and the exposure engine.
- It does not evaluate root-cause ranking or evidence faithfulness (those
  concepts don't apply to a single `analyse()` call over one input) — see
  §2 below for those metrics, which remain scenario/incident-based.

## 2. Scenario-based DB evaluation (pre-existing, extended)

Entry point: `evaluation_metric_service.run_evaluation(db, scenario_name=
"scenario_1")` → `compute_metrics_for_scenario()`, unchanged in shape from
before Phase Q. Computes, against the seeded `INC-SEED-001` incident:

- `detection_precision` / `detection_recall` / `detection_f1_score` — still
  a **type-set** metric against `Detection.sensitive_type` for this one
  legacy-path incident. This is intentionally left alone; Phase Q's
  instance-level track is additive, not a replacement, because
  `Detection` rows in this scenario are produced by the older
  `detection_service.py` path (see
  `docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md`'s "not yet unified" note),
  which was never instrumented to report ordinal instance counts.
- `masking_effectiveness`, `raw_sensitive_value_leak_count` — audit-safety
  scans over `Detection.masked_value` and the latest `LlmReport` output.
- `root_cause_top_1_accuracy` / `root_cause_top_3_accuracy` — see below.
- `evidence_faithfulness_score` — see below (rewritten in Phase Q).
- `llm_overclaim_violation_count`, `time_to_causal_localisation`,
  `fix_verification_success_rate`, `human_review_completion_rate` —
  unchanged.

### Root-cause Top-1 / Top-3 accuracy

`_root_cause_accuracy()` reads the incident's **current (latest) analysis
version** only via `causality_engine.list_root_cause_scores()` (superseded
historical batches from a prior analysis run are excluded — see Phase N
versioning, `docs/ROOT_CAUSE_ANALYSIS_VERSIONING.md`), then:

```
top1_accuracy = 1.0 if rank-1 likely_root_cause == ground_truth.expected_top_cause else 0.0
top3_accuracy = 1.0 if ground_truth.expected_top_cause in {likely_root_cause for rank in (1,2,3)} else 0.0
```

Ground truth (`expected_top_cause`) is a hand-labelled string per scenario in
`SCENARIO_GROUND_TRUTH`, matched against `docs/scenario_ground_truth.md`'s
seeded fixture.

### Evidence faithfulness — supported / unsupported / contradicted

This is the metric Phase Q rewrote most substantially. The old behaviour
treated **any non-empty `supporting_evidence_ids` list as 100% faithful**,
which is a check that a claim *cites something*, not that the citation is
real or unopposed. `classify_claim_faithfulness()` now classifies every
ranked `RootCauseScore` claim into exactly one bucket:

1. **`contradicted`** — the claim carries any entry in
   `contradicting_evidence`. Checked first: a claim with unresolved
   contradicting evidence is not "supported" no matter what it also cites.
2. **`unsupported`** — `supporting_evidence_ids` is empty, **or** it cites at
   least one identifier that does not resolve to a real, incident-scoped
   `Detection.detection_id` or `EvidenceFile.evidence_id` row
   (`_known_evidence_ids()`). A non-empty list is *not* sufficient on its
   own — every cited ID must actually exist for this incident.
3. **`supported`** — every cited ID resolves to a real record and there is
   no contradicting evidence.

`classify_evidence_faithfulness()` returns the full breakdown
(`total_claims`, `supported_count`, `unsupported_count`,
`contradicted_count`, `faithfulness_score = supported_count / total_claims`).
`evidence_faithfulness_score` (the persisted `EvaluationMetric`) is that
`faithfulness_score` value — the *share of claims that are genuinely
supported*, not merely "cite something."

**Known limitation:** `_known_evidence_ids()` only recognises `Detection`
and `EvidenceFile` identifiers as "real" evidence. A claim that legitimately
cites a `ScannerEvidenceRecord`, `CicdEvidence`, `NormalizedEvent`, or
`PrivacyAlert` ID would currently be misclassified as `unsupported` even
though the citation is valid — a scoring-conservatism gap, not a case where
the system silently accepts an unverifiable citation. Extending
`_known_evidence_ids()` to cover these entity types is listed in
`docs/LIMITATIONS_AND_FUTURE_WORK.md`.

## Backward compatibility

Everything that existed before Phase Q keeps working unchanged:

- `evaluation_metric_service.run_evaluation()`,
  `compute_metrics_for_scenario()`, `list_evaluation_metrics()`, and
  `SCENARIO_GROUND_TRUTH` are untouched in signature and behaviour (only
  `evidence_faithfulness_score`'s *internal calculation* changed, per above
  — its shape as a 0–1 `EvaluationMetric` row is identical).
- `METRIC_DEFINITIONS` gained six new entries
  (`instance_level_precision`, `instance_level_recall`,
  `instance_level_f1_score`,
  `instance_level_unsafe_exposure_classification_accuracy`,
  `instance_level_masking_success_rate`,
  `instance_level_raw_sensitive_value_leak_count`) rather than replacing any
  existing entry.
- `run_instance_level_dataset_evaluation()` is purely additive; nothing
  calls it implicitly, and `persist=False` (the default) never touches the
  database at all.
- Existing tests referencing the scenario API
  (`test_phase10_reports_metrics.py` and friends) require no changes.

## Tests

`app/tests/test_instance_level_evaluation.py` covers:
- Dataset loading and malformed-dataset error handling.
- Per-case instance counting (including the `POS-PHONE-LOG-MULTI` two-
  occurrence case).
- All negative cases produce zero unsafe-exposure findings for the wrong
  reason (timestamp-like number, Luhn failure, missing OTP auth context).
- `already_safely_masked` / `legitimate_processing` classification cases.
- Aggregate precision/recall/F1 and per-type metrics arithmetic.
- Raw-value leakage returns `0` across the whole dataset.
- `evaluation_metric_service.run_instance_level_dataset_evaluation()`
  wrapper, including the `persist=True` path writing `EvaluationMetric`
  rows.
- `classify_claim_faithfulness()` / `classify_evidence_faithfulness()`
  unit-level behaviour for supported/unsupported/contradicted claims,
  independent of the instance-level dataset.

Run:

```
cd backend
python -m pytest app/tests/test_instance_level_evaluation.py -v --tb=short
```

## Known limitations of the evaluation method overall

- Both tracks evaluate against **synthetic, hand-labelled data** (per
  the project's synthetic-data evaluation policy); neither claims to measure real-world
  precision/recall on production traffic.
- The scenario-based track still only has one scenario
  (`scenario_1`/`INC-SEED-001`); it is a regression fixture, not a
  representative sample.
- Root-cause Top-1/Top-3 accuracy has exactly one ground-truth label to
  score against; it demonstrates the mechanism works, not a statistically
  meaningful accuracy rate.
- Neither track measures latency/throughput at scale; `time_to_causal_
  localisation` is a single incident's wall-clock proxy, not a benchmark.
