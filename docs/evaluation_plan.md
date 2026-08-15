# PrivacyTrace-NP — Evaluation Plan (Phase 7.5)

## Purpose

This document defines how the PrivacyTrace-NP thesis prototype will be **evaluated** for correctness, privacy, usefulness, and research contribution. Phase 7.5 does not add product features; it plans measurement, baselines, and evidence collection for the dissertation.

The evaluation answers: *Does a privacy-preserving incident traceability workflow help investigators move from sensitive-data exposure to a likely technical cause, recommended fix, and guarded explanation faster and more safely than manual review or a basic scanner alone?*

## What is being evaluated

The **end-to-end backend workflow** (Phases 1–7):

1. Health and database readiness  
2. Synthetic evidence ingestion (`scenario_1`)  
3. Parsing into normalized events  
4. Sensitive-data detection and masking  
5. Privacy Causality Engine (likely-cause ranking, confidence bands, missing evidence)  
6. Incident trace (masked timeline + ranked causes)  
7. Guarded LLM investigation assistant (template and optional local Ollama)  
8. Stored LLM reports (hashed context, validated output)

**Out of scope for this evaluation pack:** Phase 8 human review, Phase 9 fix verification execution, dashboard UI, cloud LLMs, fine-tuning, new detection categories.

## Evaluation dimensions

| Dimension | Question | Primary artefacts |
|-----------|----------|-------------------|
| Detection | Are sensitive types found in synthetic logs/scans? | Detections table, pytest Phase 5 |
| Masking | Are raw values removed from API outputs? | Trace, explain, smoke script |
| Causality | Is the expected likely cause ranked first? | Root-cause scores, ground truth doc |
| Traceability | Is evidence linked with IDs and timeline? | `/incidents/{id}/trace` |
| LLM safety | Does explanation avoid overclaim and raw leaks? | `llm_reports`, safety rules |
| Efficiency | How long to reach likely cause? | Timestamps, TTCL script (Phase 10) |

## Metrics table

| Metric | Definition | How measured (prototype) | Target / note |
|--------|------------|---------------------------|---------------|
| Detection precision | TP / (TP + FP) | Labelled spans in Scenario 1 vs detections | Report per type |
| Detection recall | TP / (TP + FN) | Same labelled set | Report per type |
| F1-score | Harmonic mean of precision and recall | Derived from above | Primary detection summary |
| Masking effectiveness | Share of API responses with no raw sensitive substrings | `demo_smoke_test.ps1`, pytest leak lists | 100% on workflow outputs |
| Raw sensitive value leak count | Count of forbidden raw substrings in JSON responses | Automated string scan (phone, wallet, JWT, API key) | **0** |
| Root-cause top-1 accuracy | Top ranked cause matches ground truth | Compare rank 1 to `scenario_ground_truth.md` | Scenario 1: `unsafe_request_body_logging` |
| Root-cause top-3 accuracy | Ground truth in top 3 ranks | Rank list after `/incidents/analyse` | ≥ 1 for Scenario 1 |
| Evidence faithfulness | Claims reference valid evidence IDs | Manual + regex `EVD-*` in trace/explain | IDs from Scenario 1 manifest |
| LLM overclaim violation count | Outputs containing forbidden certainty phrases | `llm_safety_rules.yaml` + smoke script | **0** standalone violations |
| Time-to-Causal-Localisation (TTCL) | Time from “sensitive data found” to “likely cause with supporting evidence” | Wall-clock: detect-all end → analyse end (Phase 10 metrics) | Headline thesis metric |
| Template vs Ollama explanation | Same context, two providers | Two `POST .../explain` runs; compare structure and safety | Template always available |
| Manual review baseline vs PrivacyTrace-NP | Investigator time/steps without tool | Timed checklist vs scripted workflow | Qualitative + TTCL comparison |

## Baseline comparison plan

| Baseline | Description | Comparison method |
|----------|-------------|-------------------|
| **Manual review** | Analyst reads raw-ish logs (synthetic only), notes endpoint and guess at cause | Record steps, time, whether raw values were written in notes (should not in thesis demo) |
| **Basic sensitive-data scanner** | Regex scan only, no causality or trace | Run detection rules in isolation; no ranking or fix draft |
| **PrivacyTrace-NP (full workflow)** | Mask → correlate → rank → trace → guarded explain | `demo_smoke_test.ps1` + screenshot checklist |

**Hypothesis:** PrivacyTrace-NP reduces TTCL and produces a more complete, privacy-safe evidence trail than baselines, at the cost of depending on evidence completeness (lower confidence when evidence is missing).

## Labelled scenario evaluation plan

1. **Ground truth:** `docs/scenario_ground_truth.md` (Scenario 1 = wallet transfer API logging).  
2. **Run pipeline:** `scripts/demo_reset.ps1` then `scripts/demo_smoke_test.ps1`.  
3. **Record:** detection counts by type, top-3 causes, confidence bands, missing-evidence list, explain output fields.  
4. **Score:** top-1 / top-3 accuracy, faithfulness (IDs cited), leak count (must be 0).  
5. **Repeat** after rule or parser changes; keep pytest green (`pytest app/tests -v`).

Additional scenarios (future): extend ground-truth table; do not expand scope in Phase 7.5.

## LLM safety evaluation

| Check | Method | Pass criterion |
|-------|--------|----------------|
| Masked-only context | Code review + input guard tests | No raw patterns in `build_llm_context` path |
| Output structure | `validate_investigation_output` | Required keys present |
| Overclaim phrases | `llm_safety_rules.yaml` list | 0 unresolved violations after sanitization |
| Evidence grounding | Likely-cause text references `EVD-*` | Present in template/Ollama output |
| Fallback | Ollama off → template | `provider_used: template`, HTTP 200 |
| Storage | `llm_reports` row | Only hash + JSON output, no prompt body |

Compare **template** vs **Ollama** on same incident: same ranking input, diff in prose quality; safety gates must pass for both.

## Privacy evaluation

- **Rule:** Raw sensitive values never appear in trace, explain, or list-report API JSON (aligned with `PRIVACYTRACE_RULES.md`).  
- **Verification:** pytest Phases 5–7 integration tests; `demo_smoke_test.ps1` forbidden substring scan.  
- **LLM:** Only masked fields and metadata in context; `input_context_hash` stored, not full prompt.  
- **Limitation:** Synthetic data only; no real customer payloads.

## Limitations

- Single primary labelled scenario (`INC-SEED-001` / `scenario_1`) for quantitative claims in the prototype phase.  
- Causality is **rule-based**, not ML; rankings depend on evidence types present.  
- LLM is **advisory**; does not replace human review or prove root cause.  
- TTCL requires consistent manual or scripted timestamps until Phase 10 metrics API exists.  
- No production deployment, multi-tenant, or performance benchmarking in Phase 7.5.  
- Ollama results vary by model; template is the reproducible baseline for demos.

## How results support the thesis

1. **Problem:** Alerts lack remediation-ready, privacy-safe traceability.  
2. **Solution:** Documented workflow with masking, causality engine, and guarded explanation.  
3. **Evidence:** Metrics table above + screenshots (`screenshot_checklist.md`) + repeatable scripts.  
4. **Contribution:** Privacy-preserving **trace** linking endpoint, masked detections, ranked likely cause, fix draft, and human-review-oriented wording—not merely detection counts.  
5. **Headline claim:** Improved **Time-to-Causal-Localisation** and **zero raw leaks** vs baselines, with explicit **missing-evidence** and **overclaim** reporting when certainty is not justified.

## Related artefacts (Phase 7.5)

| File | Role |
|------|------|
| `docs/scenario_ground_truth.md` | Expected outputs for Scenario 1 |
| `docs/screenshot_checklist.md` | Report and viva screenshots |
| `docs/demo_walkthrough.md` | 5-minute live demo script |
| `scripts/demo_reset.ps1` | Clean DB + migrate + seed |
| `scripts/demo_smoke_test.ps1` | End-to-end API validation |

Phase 8+ evaluation (review decisions, fix verification pass rate) is documented here for completeness but **not implemented** in the current codebase.
