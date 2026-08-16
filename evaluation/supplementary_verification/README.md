# Supplementary controlled verification evaluation

Separate from the sealed held-out 80. Does not import ground truth into PrivacyTrace runtime.

Calls frozen **pure** functions only:

- `fix_verification_service.verification_status_for_retest`
- `counterfactual_analysis_service.classify_stability`
- `root_cause_evidence_strength_service.compute_causal_evidence_strength_from_context`
- `causality_engine.apply_staleness_to_rows` / `supersede_rows`
- `verified_outcome_learning_service.eligibility_for_learning`

Does **not** call `verify_fix`, `record_controlled_retest`, or `execute_controlled_rollback`.

Rollback cases SV-023 and SV-024 are declared NOT EXECUTED (DB + sandbox required).
