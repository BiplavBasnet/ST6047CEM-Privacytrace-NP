# PrivacyTrace-NP — Baseline Comparison Plan (Phase 10)

This document structures how PrivacyTrace-NP is compared against two baselines for the thesis evaluation. It does not implement a full manual user study; it records where baseline values can be entered after experiments.

## Research question

Does a privacy-preserving incident traceability workflow reduce **Time-to-Causal-Localisation (TTCL)** and improve **evidence-grounded, privacy-safe** investigation outcomes compared with manual review or pattern-only scanning?

## Baseline 1 — Manual review

| Aspect | Description |
|--------|-------------|
| **Method** | A human investigator inspects synthetic logs, scan JSON, and deployment notes without PrivacyTrace-NP automation. |
| **Measures** | TTCL (minutes from noticing sensitive data to stating a likely cause with cited evidence IDs); correctness of top likely cause; count of missed evidence types; accidental raw-value notes (must be zero in thesis demos). |
| **Expected weakness** | Slower TTCL; inconsistent masking in notes; weaker traceability across evidence types. |
| **Recording** | Use `docs/evidence_pack/manual_baseline_log.md` (create during study) or spreadsheet columns: `ttcl_seconds`, `top_cause_correct` (0/1), `missed_evidence_count`. |

## Baseline 2 — Basic scanner (pattern-only)

| Aspect | Description |
|--------|-------------|
| **Method** | Run sensitive-data regex rules (same family as Phase 5) on sample files without causality ranking, trace assembly, guarded LLM, review, or fix verification. |
| **Measures** | Detection precision/recall/F1 only; no root-cause top-1 accuracy; no fix verification success rate; no evidence faithfulness score. |
| **Expected weakness** | Detects patterns but does not link endpoint, rank likely cause, mask for reporting pipeline, or verify fixes. |
| **Recording** | Compare `detection_*` metrics from `/metrics/evaluation` with causality and verification metrics set to N/A for this baseline. |

## PrivacyTrace-NP (full workflow)

| Aspect | Description |
|--------|-------------|
| **Method** | `scripts/demo_smoke_test.ps1` + Phase 10 `/metrics/evaluation/run` after pipeline through review (and optional fix verification). |
| **Headline metrics** | `time_to_causal_localisation`, `root_cause_top_1_accuracy`, `raw_sensitive_value_leak_count`, `llm_overclaim_violation_count`, `fix_verification_success_rate`, `human_review_completion_rate`. |
| **Evidence** | `docs/evidence_pack/` screenshots and `api_outputs/` JSON. |

## Comparison table (fill during evaluation)

| Metric | Manual baseline | Basic scanner | PrivacyTrace-NP |
|--------|---------------|---------------|-----------------|
| TTCL (seconds) | _TBD_ | N/A | from API |
| Root-cause top-1 accuracy | _TBD_ | N/A | from API |
| Detection F1 | _TBD_ | _TBD_ | from API |
| Raw leak count in outputs | _TBD_ | _TBD_ | from API |
| Evidence IDs in conclusion | _TBD_ | N/A | from API |
| Fix verification | N/A | N/A | from API |

## Limitations

- Prototype uses **Scenario 1** (`INC-SEED-001`) as the primary labelled case.
- Manual baseline timings are investigator-dependent; report methodology in thesis chapter.
- Basic scanner baseline reuses detection rules but not the full ingestion/trace pipeline.
