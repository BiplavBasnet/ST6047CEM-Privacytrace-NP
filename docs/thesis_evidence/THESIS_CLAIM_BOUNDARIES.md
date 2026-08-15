# Thesis claim boundaries

APPLICATION_FREEZE_SHA: `8b22b670a82b61882cb841b10a9f4d364de30bc7`  
EVALUATION_RUN_ID: `EVAL-HO80-20260817-1`  
SUPPLEMENTARY_EVAL_ID: `SUPP-VERIFY-20260817-1`

This file states what the evidence supports. It does not enlarge claims.

## Quantitatively evaluated

- Sensitive-instance detection on the sealed held-out 50 detection cases (F1 0.975610; TP 40, FP 2, FN 0)
- Exposure-decision classification (39/40 = 0.975; HO-021 `uncertain` vs `unsafe_exposure`)
- Controlled RCA **signal-ranking** subset (20/20 Top-1 and Top-3 on synthetic predefined signals — not real-world RCA accuracy)
- Privacy leakage checks on held-out engine outputs (0 raw leaks)
- Supplementary verification **policy-function** metrics (22 executed cases; rollback not executed)
- Supplementary causality-engine ablation (12 synthetic `EvidenceContext` cases; Top-1 unchanged; scores/Top-3 changed)

## Demonstrated / runtime verified

- End-to-end governed incident lifecycle on `INC-LIVE-E178AEC313`
- Human review, remediation, implementation, controlled retest, verification outcome, reporting
- RBAC negative path and human-gate block
- Backend restart persistence and browser refresh hydration
- Runtime Connector (host-side NepalFin path)
- Evidence Import
- Controlled ScannerBridge import (not a live scanner process)
- NepalFin synthetic scenario path (ingest demonstrated; SS-068 INCONCLUSIVE for a second full lifecycle)

## Not fully evaluated / unavailable

- Real Wazuh Manager
- Real GitHub-hosted workflow
- Uncontrolled real-world RCA accuracy
- Production-scale performance
- Generalisation beyond synthetic/evaluation datasets
- Real-world Nepal financial-service deployment
- Complete Dockerised NepalFin→PrivacyTrace lifecycle
- Sandbox rollback execution (frozen API requires DB + patch snapshot)
- Persisted `complete_passed_chain` learning gate (only the coarse public `eligibility_for_learning` was scored)
- Real AI-provider path (SS-028 not captured)
