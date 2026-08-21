# Final Evaluation Results

> **PRELIMINARY / DEVELOPMENT-SET EVALUATION**
>
> **NOT THE FINAL INDEPENDENT HELD-OUT THESIS EVALUATION**

Phase: **SOURCE-AWARE VERIFIED REMEDIATION COMPLETION AND THESIS EVALUATION HARDENING**

Metrics source: `.local_eval_runtime/thesis_eval_metrics.json` (regenerated via `python -m app.services.thesis_evaluation_runner`).

## Detection (v2 corpus)

| Metric | Value |
|---|---|
| Dataset size | 335 |
| Positive / negative | 128 / 207 |
| TP / FP / FN / TN | 132 / 20 / 0 / 184 |
| Precision / Recall / F1 | 0.8684 / 1.0 / 0.9296 |
| Raw-value leakage | **0** |

Bearer-token false positives (20) drive precision below 1.0. Unsafe-exposure classification accuracy on this corpus remains weak (~0.09) — detection of types ≠ correct exposure decision labels. Details: `DETECTION_EVALUATION_RESULTS.md`.

## Root-cause (36 scenarios)

| Metric | Value |
|---|---|
| Top-1 | 30/36 = **83.3%** |
| Top-3 | 36/36 = **100%** |
| Component localisation | 34/36 = **94.4%** |

All six Top-1 failures analysed in `ROOT_CAUSE_EVALUATION_RESULTS.md`.

## Evidence faithfulness (5 claims)

| Status | Count |
|---|---|
| Supported | 2 |
| Partially supported | 1 |
| Unsupported | 1 |
| Contradicted | 1 |
| Strict faithfulness | **0.40** |

## AI remediation (15 scenarios)

| Metric | Value |
|---|---|
| Primary remediation accuracy | 86.7% |
| Component targeting | 86.7% |
| Source localisation | 20.0% |
| Unsafe remediation count | 2 |
| Unsupported source claims | 2 |
| Test-plan adequacy | 80.0% |

## Gold-standard verified remediation

Service-level proof: `app/tests/test_gold_standard_verified_remediation.py` (source evidence resolve / invent-block / patch→sandbox→test→verify→persist→rollback).

Migration: `024_verified_remediation_completion` (`patch_proposals`, `verified_remediation_cases`, `remediation_playbooks`).

## Honesty bounds

- Offline RC ranker ≠ production `causality_engine`.
- Full 45-step browser demo of gold sandbox apply was not re-executed in this phase; API/service gold test is the authoritative patch→learning proof.
- Learning is PostgreSQL-backed (not process memory).
