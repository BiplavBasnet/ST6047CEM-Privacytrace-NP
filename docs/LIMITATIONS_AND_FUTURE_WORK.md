# Limitations and Future Work

## Current limitations

1. Root-cause offline evaluation uses a deterministic signal ranker — not identical to production `causality_engine`.
2. Detection v2 still shows weak unsafe-exposure **decision** label accuracy despite strong type detection.
3. Bearer-token false positives reduce precision (~0.87 overall).
4. Evidence-faithfulness evaluation uses a small claim set (n=5) as a method proof.
5. AI remediation source-localisation accuracy remains low (20%) when evidence is sparse by design.
6. Controlled patch apply is allowlisted gold-fixture controlled local test workspace only (Option B) — not a general multi-repo CI bot.
7. Full interactive browser proof of sandbox apply → learning was not re-run in this phase (service gold test is authoritative).
8. Scenario / held-out thesis evaluation is **deferred** and was not started in the workflow provenance hardening phase.

## Future work

- Align production causality ranking with thesis scenario matrix.
- Expand claim-level faithfulness onto live diagnosis outputs.
- Reduce bearer-token FP via stronger negative/context rules.
- Improve unsafe-exposure decision labelling evaluation.
- Optional second similar-incident ranking demo in browser after durable playbook seed.
- Resume deferred scenario/held-out evaluation after provenance hardening stabilises.
