# Scenario coverage matrix (held-out 80)

APPLICATION_FREEZE_SHA: `8b22b670a82b61882cb841b10a9f4d364de30bc7`  
NEPALFIN_LAB_SHA: `ae77b8ee4c62b5171c2b3ca08a44fe0ee405c0ee`  
HELD_OUT_80_SHA256: `2cd8f1c3b2d831cc5f042e06475868d9b3f583ff75e3f7a7971f46e404cf572b`  
Sealed: `2026-08-17T10:26:41Z`  
Pack: `evaluation/heldout/` (not `backend/app/evaluation_data/`)

Development/preliminary corpora in `backend/app/evaluation_data/` are **not** this evaluation.

## Matrix

| IDs | Family | Channel / method | In performance denominator? | Notes |
|---|---|---|---|---|
| HO-001–050 | Detection | Frozen `sensitive_exposure_engine.analyse` on synthetic Nepal DFS-shaped inputs | Yes (n=50) | Inputs in `inputs.yaml`; labels only in `ground_truth.yaml` |
| HO-051–070 | RCA | Signal→cause ranking copied from freeze weights; **no GT append** | Yes (n=20) | Application runner appends GT; harness does not |
| HO-071–074 | ScannerBridge | Controlled scanner-shaped JSON → `scanner_safety_service.sanitize_payload` | Yes (n=4) | Label: **CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION**. Not real external scanner integration |
| HO-075–076 | Wazuh | — | **No** | **NOT AVAILABLE** this run. No SS-017 |
| HO-077–078 | GitHub hosted workflow | — | **No** | **NOT AVAILABLE** this run. No SS-018 |
| HO-079 | RBAC | Phase 1 UI/API | **No** (qualitative) | Proven SS-052 authorised / SS-053 denied |
| HO-080 | Human gate | Phase 1 UI | **No** (qualitative) | Proven SS-054 Verify Fix blocked |

Supplementary verification (`evaluation/supplementary_verification/`) is **not** part of this 80. Rollback cells there are NOT EXECUTED.


## Denominators used in Phase 5

- Detection instance metrics: 50 cases  
- RCA Top-1 / Top-3 / component: 20 cases  
- Controlled scanner sanitise: 4 cases  
- Wazuh + GitHub: excluded  
- RBAC + human-gate: qualitative PASS from Phase 1, excluded from detector/RCA denominators  

Do not mix freeze pytest counts (885/173/75) with these research metrics.
