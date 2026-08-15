# Evaluation summary (thesis evidence pack)

Date: 2026-08-17  
APPLICATION_FREEZE_SHA: `8b22b670a82b61882cb841b10a9f4d364de30bc7`  
Hygiene snapshot: `e7ca04b7ec517827a783f751fec28036f67d8762`  
NEPALFIN_LAB_SHA: `ae77b8ee4c62b5171c2b3ca08a44fe0ee405c0ee`  
EVALUATION_RUN_ID: `EVAL-HO80-20260817-1`  
HELD_OUT_80_SHA256: `2cd8f1c3b2d831cc5f042e06475868d9b3f583ff75e3f7a7971f46e404cf572b`  
SUPPLEMENTARY_EVAL_ID: `SUPP-VERIFY-20260817-1`  
ABLATION_ID: `ABL-RCA-20260817-1`  
Application behaviour changes during this evidence-closure task: **NO**.  
Phase 5 / supplementary application correction cycles: **0**.

Freeze pytest counts (885 / 173 / 75) are **implementation verification**. They are not research performance.

---

## 1. Evaluated application identity

Frozen application: `8b22b670a82b61882cb841b10a9f4d364de30bc7`.  
HEAD at closure start: `25250f4172debfa5b37774c5e6e1bf97cb508d7e` (freeze plus two documentation-only `CODE_FREEZE_MANIFEST.md` commits). Alembic head `037_connector_client_event_id`. Live `GET /health` HTTP 200, `database: connected` (SS-078).

---

## 2. Whole-project real-user runtime

`FULL PROJECT RUNTIME VERIFIED` on the freeze SHA. Authoritative incident `INC-LIVE-E178AEC313` (`fixed`). Path: setup → org → auth → ingest → incident → evidence/provenance → RCA → Human Review → remediation → implementation → approved test → controlled retest → verification → report. Restart persistence and refresh hydration held. RBAC negative: SS-053. Human-gate negative: SS-054.

Core end-to-end application workflow was successfully verified, with documented non-blocking UI/data consistency limitations:

- load-sample evidence `EVD-S1-*` linked to missing `INC-SEED-001`
- report sidebar next-action still “Add Retest Evidence” after report ready
- live RCA cause is `unsafe_request_body_logging` on the synthetic wallet leak, not the separate gold-standard header-logging SAST fixture

These were not patched.

---

## 3. NepalFin experimental lab

NepalFin is a **synthetic experimental financial-service laboratory**, SHA `ae77b8ee4c62b5171c2b3ca08a44fe0ee405c0ee`. It is not part of the PrivacyTrace application freeze. Synthetic sensitive values were used. Runtime ingestion was demonstrated on the **supported host-side path** (lab uvicorn on 8088 → PrivacyTrace `127.0.0.1:8000`). Windows Docker/container-to-host networking limited the full direct container path. SS-068 remains **INCONCLUSIVE**: event ingested; a new RCA→remediation→verification cycle did not run on that emit. This is not a complete Dockerised end-to-end PrivacyTrace lifecycle.

---

## 4. Connector validation

| Connector | Status |
|---|---|
| Runtime | VERIFIED (SS-004–009) |
| Evidence Import | VERIFIED (`EVD-4885374839c5`, SS-014 / SS-014B) |
| ScannerBridge | **CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION** (SS-016). Not a live external scanner executable |
| Wazuh | **NOT AVAILABLE** (no SS-017; excluded from denominators) |
| GitHub hosted workflow | **NOT AVAILABLE** (no SS-018; excluded from denominators) |

---

## 5. Held-out 80 methodology

Pack: `evaluation/heldout/` (`inputs.yaml` vs `ground_truth.yaml`). Not `backend/app/evaluation_data/` (DEVELOPMENT/PRELIMINARY). Runtime does not import ground truth. SS-070 sealed the pack; behaviour was then locked. Run once: `EVAL-HO80-20260817-1`. RCA used copied signal weights **without** appending ground truth to the ranked list. Wazuh/GitHub and qualitative RBAC/human-gate cells are excluded from performance denominators.

---

## 6. Detection results

n = 50 instance-level cases. TP 40, FP 2, FN 0. Precision 0.952381, recall 1.000000, F1 0.975610. Exposure-decision accuracy 39/40 = 0.975000 (HO-021 miss). Masking success 1.000000; raw-leak count 0.

---

## 7. RCA results

The controlled held-out RCA signal-ranking subset achieved 20/20 Top-1 and 20/20 Top-3 correctness. These scenarios used synthetic predefined evidence signals and therefore do not establish equivalent accuracy for uncontrolled real-world investigations.

Supplementary insufficient-evidence tests (SV-016–018) are reported in section 9, not mixed into the 20/20.

---

## 8. Privacy leakage results

Held-out leak check: 0 raw sensitive values in engine finding blobs (masking success 1.0). Screenshots exclude `ptig_` plaintext, passwords, and raw PII.

---

## 9. Supplementary verification evaluation

`SUPP-VERIFY-20260817-1`. 24 declared; 22 executed via frozen pure functions; SV-023/024 rollback **NOT EXECUTED** (DB + sandbox required).

| Metric | n | Accuracy |
|---|---|---|
| FixVerification PASS | 4 | 1.0 |
| FixVerification FAIL | 4 | 1.0 |
| FixVerification INCONCLUSIVE | 4 | 1.0 |
| Overall verification-state | 12 | 1.0 |
| Mismatched-retest safe handling | 3 | 1.0 |
| Insufficient-evidence RCA | 3 | 1.0 |
| Stale-chain rejection | 2 | 1.0 |
| Verified-learning eligibility (coarse public gate) | 2 | 1.0 |
| Rollback | 0 executed | LIMITATION |

One allowed harness correction mapped `causal_strength_level` from the frozen payload; inputs/GT were not changed. Application fixes after seeing results: 0.

This measures the **exported policy functions**, not a second 24-incident UI workflow.

---

## 10. Ablation / baseline

Performed: `ABL-RCA-20260817-1`, 12 synthetic `EvidenceContext` cases, frozen `causality_engine.rank_causes`. Not comparable to held-out 20/20.

| Condition | Top-1 cause (all 4 bases) | Mean Top-1 score | Insufficient |
|---|---|---|---|
| A detector/runtime only | `unsafe_request_body_logging` | 0.55 | 0 |
| B + scanner | same Top-1; `incomplete_redaction_rule` enters Top-3 | 0.55 | 0 |
| C + scanner + deployment_log | same Top-1; score rises | 0.80 | 0 |

Component localisation is not a field on `ScoredCause` in this interface (reported null). Additional evidence changed scores and Top-3 membership, not Top-1, on this synthetic base.

---

## 11. Governance / RBAC / human-gate

Phase 1 qualitative: authorised incident list (SS-052); `/users` denied HTTP 403 (SS-053); Verify Fix blocked before review (SS-054). HO-079/HO-080 excluded from detector denominators.

---

## 12. Failure analysis

Held-out (not patched, not rerun):

- **HO-021** — expected `unsafe_exposure`, actual `uncertain`. Type still TP. Effect: exposure-decision accuracy 39/40 = 0.975.
- **HO-039** — false positive on non-Nepal 10-digit `contact_number`.
- **HO-046** — false positive on already-redacted `Bearer ****`.

Supplementary: no scenario-level failures among the 22 executed cases. Rollback not executed.

Ablation: Top-1 did not change when scanner/deployment evidence was added on this base (limitation of the synthetic construction, not a hidden success).

---

## 13. External-integration limitations

Wazuh Manager and GitHub-hosted workflow were not available. ScannerBridge is controlled import only. NepalFin Docker-to-host path was not proven. SS-028 (real AI provider) was not captured.

---

## 14. Threats to validity

Held-out detection is offline `analyse()` on synthetic text, not 50 UI incidents. Held-out RCA is a signal-token heuristic, not the live causality engine (the ablation is). Supplementary verification calls pure policy functions, not `verify_fix` persistence. Learning eligibility uses the coarse public gate, not DB `complete_passed_chain`. Synthetic NepalFin is not a production DFS deployment. Identical screenshots (SS-010/011, SS-006/007/067, SS-055/059/080) are reused viewports, not independent observations.

---

## 15. Thesis claim boundaries

See [`THESIS_CLAIM_BOUNDARIES.md`](THESIS_CLAIM_BOUNDARIES.md).

**MAIN figures (14 unique viewports):** SS-001, SS-010, SS-012, SS-013, SS-019, SS-023, SS-027, SS-033, SS-045, SS-054, SS-055, SS-060, SS-071, SS-078.  
SS-068 is a LIMITATION figure, not a main success screenshot.
