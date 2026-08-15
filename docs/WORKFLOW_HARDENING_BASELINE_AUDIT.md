# Workflow Hardening Baseline Audit

Phase: **WORKFLOW PROVENANCE, VERIFICATION INTEGRITY, AI REMEDIATION CONSOLIDATION AND OPERATIONAL HARDENING**

Date: 2026-08-13  
Alembic head at audit start: `024_verified_remediation_completion`

## Confirmed problems

| # | Problem | Affected files | Current behaviour |
|---|---|---|---|
| 1 | No first-class RootCauseAnalysis parent | `root_cause_score.py`, `causality_engine.py` | Version fields denormalized on each score row |
| 2 | Review unbound to analysis | `review_decision.py`, `review_service.py` | Gate = “any RootCauseScore exists” |
| 3 | Diagnosis snapshot ≠ RCA snapshot | `ai_remediation_diagnosis_service.py` | Own hash; nullable `root_cause_analysis_id` |
| 4 | Competing remediation systems | `ai_remediation_service.py` + diagnosis + FE panels | Legacy + problem-specific both live |
| 5 | RemediationAction lacks provenance FKs | `remediation_action.py` | Manual tracker only |
| 6 | Patch does not require RemediationAction | `controlled_patch_service.py` | `remediation_action_id=None` on draft |
| 7 | No persisted TestExecution | `sandbox_test_execution_service.py` | Ephemeral dict |
| 8 | No VerificationOutcome entity | `verification_outcome_service.py` | Dict only; unused by routers |
| 9 | Learning field semantics wrong | `verified_outcome_learning_service.py` | category←component; exposure=None; type←text |
| 10 | Live monitor drops correlation | `live_monitor_service.py` | NormalizedEvent without trace_id |
| 11 | Dual fingerprint regimes | `detection_service.hash_raw_value` | Unkeyed SHA256 fallback still written |
| 12 | Workflow ignores diagnosis/patch/verify chain | `incident_workflow_service.py` | Status-only stages |
| 13 | Source localisation first-file bias | locator service | Needs ranked scoring |
| 14 | Workspace integrity incomplete | patch apply | Diff hash only; no recovery_required |

## Chosen implementation strategy

Ponytail / targeted refactor:

1. Add `RootCauseAnalysis` parent + link scores; backfill from existing `analysis_id` batches.
2. Bind `ReviewDecision` to `root_cause_analysis_id` + `evidence_snapshot_hash`; enforce match for progression.
3. Invalidate analysis (and progression) on evidence revision; keep history.
4. Authoritative `GET .../workflow-state` facts from DB provenance chain.
5. Consolidate remediation: diagnosis path is authoritative; legacy UI deprecated (API kept read-compatible).
6. Truthful `generation_mode`; AI fallback + prompt-injection guards.
7. Ranked source localisation; `exact_source_location_known` only above threshold.
8. RemediationAction = canonical approved plan; PatchProposal requires it.
9. Persist `RemediationTestExecution` + `VerificationOutcome` + exposure verification profile.
10. Fix learning semantics + eligibility; HMAC-only fingerprints; live correlation; unique traces; RBAC on sensitive writes.
11. Controlled patch scope: **Option B** — gold-fixture proof-of-concept, documented honestly as controlled local test workspace.

## Intentionally deferred

- Scenario / held-out thesis evaluation (explicitly deferred).
- Real process/network isolation “secure sandbox” (wording: controlled local test workspace).
- Kafka / Neo4j / Redis / blockchain.
- Full multi-person four-eyes enforcement (document single-operator Bachelor prototype).
- Generalised multi-repo autonomous patch engine.

## Intentionally deferred evaluation note

Scenario/held-out evaluation documentation and runs are **not** started in this phase.
