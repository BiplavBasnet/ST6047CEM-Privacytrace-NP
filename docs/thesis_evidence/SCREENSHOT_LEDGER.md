# Thesis screenshot ledger

APPLICATION_FREEZE_SHA: `8b22b670a82b61882cb841b10a9f4d364de30bc7`
Hygiene snapshot: `e7ca04b7ec517827a783f751fec28036f67d8762`
NEPALFIN_LAB_SHA: `ae77b8ee4c62b5171c2b3ca08a44fe0ee405c0ee`
EVALUATION_HARNESS_SHA256: `3a50c3d78ad0374c6f26e92f31e5aad972eb2455d538aa95f3cac2f32fd7f6ab`
HELD_OUT_80_SHA256: `2cd8f1c3b2d831cc5f042e06475868d9b3f583ff75e3f7a7971f46e404cf572b`
EVALUATION_RUN_ID: `EVAL-HO80-20260817-1`
Date: 2026-08-17

Sensitive-information rule: no passwords, `.env`, private keys, `ptig_` plaintext, API tokens, DB credentials, raw PII/KYC, auth headers, or full secret-scanner matches.

Wazuh: NOT AVAILABLE (no SS-017). GitHub hosted workflow: NOT AVAILABLE (no SS-018).

## Status catalogue SS-001–SS-080

Each planned ID has exactly one status. Identical files are not independent evidence.

| ID | Status | Placement | Note |
|---|---|---|---|
| SS-001 | CAPTURED | MAIN | Dashboard |
| SS-002 | CAPTURED | APPENDIX | Integrations |
| SS-003 | NOT CAPTURED | — | State not independently captured |
| SS-004 | CAPTURED | APPENDIX | Runtime CLI install |
| SS-005 | CAPTURED | APPENDIX | NepalFin target layout |
| SS-006 | CAPTURED | APPENDIX | Runtime emit |
| SS-007 | CAPTURED | APPENDIX | SAME SOURCE VIEWPORT AS SS-006 (identical bytes) |
| SS-008 | CAPTURED | APPENDIX | Source spoof |
| SS-009 | CAPTURED | APPENDIX | Duplicate event |
| SS-010 | CAPTURED | MAIN | Sensitive exposure detected |
| SS-011 | CAPTURED | APPENDIX | SAME SOURCE VIEWPORT AS SS-010 (identical bytes) |
| SS-012 | CAPTURED | MAIN | Incident created |
| SS-013 | CAPTURED | MAIN | Canonical evidence |
| SS-014 | CAPTURED | APPENDIX | Evidence Import |
| SS-014B | CAPTURED | APPENDIX | Provenance companion of SS-014 (not a new SS-NNN slot) |
| SS-015 | CAPTURED | APPENDIX | Phase-1 evidence provenance |
| SS-016 | CAPTURED | APPENDIX | CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION |
| SS-017 | NOT AVAILABLE | — | Wazuh |
| SS-018 | NOT AVAILABLE | — | GitHub hosted workflow |
| SS-019 | CAPTURED | MAIN | RCA |
| SS-020 | NOT CAPTURED | — | State not independently captured |
| SS-021 | NOT CAPTURED | — | State not independently captured |
| SS-022 | NOT CAPTURED | — | State not independently captured |
| SS-023 | CAPTURED | MAIN | Human review |
| SS-024 | NOT CAPTURED | — | State not independently captured |
| SS-025 | NOT CAPTURED | — | State not independently captured |
| SS-026 | NOT CAPTURED | — | State not independently captured |
| SS-027 | CAPTURED | MAIN | Remediation |
| SS-028 | NOT CAPTURED | — | Real AI-provider path not verified |
| SS-029 | NOT CAPTURED | — | State not independently captured |
| SS-030 | NOT CAPTURED | — | State not independently captured |
| SS-031 | NOT CAPTURED | — | State not independently captured |
| SS-032 | NOT CAPTURED | — | State not independently captured |
| SS-033 | CAPTURED | MAIN | Implementation record |
| SS-034 | NOT CAPTURED | — | State not independently captured |
| SS-035 | NOT CAPTURED | — | State not independently captured |
| SS-036 | NOT CAPTURED | — | State not independently captured |
| SS-037 | NOT CAPTURED | — | State not independently captured |
| SS-038 | CAPTURED | APPENDIX | Test execution |
| SS-039 | NOT CAPTURED | — | State not independently captured |
| SS-040 | NOT CAPTURED | — | State did not occur independently |
| SS-041 | NOT CAPTURED | — | State did not occur independently |
| SS-042 | NOT CAPTURED | — | State not independently captured |
| SS-043 | NOT CAPTURED | — | State not independently captured |
| SS-044 | NOT CAPTURED | — | State not independently captured |
| SS-045 | CAPTURED | MAIN | Verification lineage |
| SS-046 | NOT CAPTURED | — | State not independently captured |
| SS-047 | NOT CAPTURED | — | State not independently captured |
| SS-048 | NOT CAPTURED | — | State not independently captured |
| SS-049 | NOT CAPTURED | — | State not independently captured |
| SS-050 | NOT CAPTURED | — | State not independently captured |
| SS-051 | CAPTURED | APPENDIX | Audit trail |
| SS-052 | CAPTURED | APPENDIX | Authorised RBAC |
| SS-053 | CAPTURED | APPENDIX | Access denied |
| SS-054 | CAPTURED | MAIN | Human gate blocked |
| SS-055 | CAPTURED | MAIN | Final incident report |
| SS-056 | CAPTURED | APPENDIX | Report provenance |
| SS-057 | CAPTURED | APPENDIX | Report verification |
| SS-058 | NOT CAPTURED | — | State not independently captured |
| SS-059 | CAPTURED | APPENDIX | SAME SOURCE VIEWPORT AS SS-055 (identical bytes) |
| SS-060 | CAPTURED | MAIN | NepalFin overview |
| SS-061 | CAPTURED | APPENDIX | NepalFin auth |
| SS-062 | CAPTURED | APPENDIX | NepalFin KYC |
| SS-063 | CAPTURED | APPENDIX | NepalFin wallet |
| SS-064 | CAPTURED | APPENDIX | NepalFin remittance |
| SS-065 | CAPTURED | APPENDIX | NepalFin merchant |
| SS-066 | CAPTURED | APPENDIX | NepalFin unsafe path |
| SS-067 | CAPTURED | APPENDIX | SAME SOURCE VIEWPORT AS SS-006 (identical bytes) |
| SS-068 | INCONCLUSIVE | LIMITATION | NepalFin emit ingested; no new RCA cycle |
| SS-069 | CAPTURED | APPENDIX | NepalFin coverage |
| SS-070 | CAPTURED | APPENDIX | Held-out 80 sealed |
| SS-071 | CAPTURED | MAIN | Held-out results |
| SS-072 | CAPTURED | APPENDIX | Application freeze identity |
| SS-073 | CAPTURED | APPENDIX | Alembic head |
| SS-074 | DERIVED | APPENDIX | PostgreSQL-critical freeze summary |
| SS-075 | CAPTURED | APPENDIX | Full backend log |
| SS-076 | DERIVED | APPENDIX | Frontend tests freeze summary |
| SS-077 | DERIVED | APPENDIX | Frontend build freeze summary |
| SS-078 | CAPTURED | MAIN | Live /health |
| SS-079 | CAPTURED | APPENDIX | Runtime workflow start |
| SS-080 | CAPTURED | APPENDIX | SAME SOURCE VIEWPORT AS SS-055 (identical bytes) |

---

## SS-072

| Field | Value |
|---|---|
| Filename | `screenshots/SS-072-application-freeze.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-baseline |
| What is visible | Application freeze SHA, hygiene snapshot SHA, SEALED status |
| Academic purpose | Identify the frozen implementation under evaluation |
| Suggested thesis location | Appendix — freeze identity |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | Repeatable `git log -1` + CODE_FREEZE_MANIFEST |

## SS-073

| Field | Value |
|---|---|
| Filename | `screenshots/SS-073-alembic-final-head.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-alembic |
| What is visible | Single Alembic head `037_connector_client_event_id`; no 038 |
| Academic purpose | Schema identity of the freeze |
| Suggested thesis location | Appendix — database freeze |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No credentials |
| Evidence source | Repeatable `alembic heads` |

## SS-074

| Field | Value |
|---|---|
| Filename | `screenshots/SS-074-postgresql-critical.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-critical-db |
| What is visible | 75 passed, 0 failed (DERIVED FREEZE SUMMARY) |
| Academic purpose | PostgreSQL-critical freeze gate |
| Suggested thesis location | Appendix — implementation verification |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | DERIVED FREEZE SUMMARY from `docs/CODE_FREEZE_MANIFEST.md`. Original isolated critical log was a contended 74/75 run, not used as the sealed count. |

## SS-075

| Field | Value |
|---|---|
| Filename | `screenshots/SS-075-full-backend-regression.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-backend |
| What is visible | 885 passed, 2 skipped, 0 failed; skip names recorded |
| Academic purpose | Full backend freeze gate |
| Suggested thesis location | Appendix — implementation verification |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | Original saved log `freeze_logs/full_backend.log` |

## SS-076

| Field | Value |
|---|---|
| Filename | `screenshots/SS-076-frontend-tests.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-frontend-tests |
| What is visible | 173 passed, 0 failed (DERIVED FREEZE SUMMARY) |
| Academic purpose | Frontend unit/UI freeze gate |
| Suggested thesis location | Appendix — implementation verification |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | DERIVED FREEZE SUMMARY from `docs/CODE_FREEZE_MANIFEST.md`. No preserved freeze-run vitest log. |

## SS-077

| Field | Value |
|---|---|
| Filename | `screenshots/SS-077-frontend-build.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-frontend-build |
| What is visible | Production build PASS (DERIVED FREEZE SUMMARY) |
| Academic purpose | Production frontend build freeze gate |
| Suggested thesis location | Appendix — implementation verification |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | DERIVED FREEZE SUMMARY from `docs/CODE_FREEZE_MANIFEST.md`. Older 2026-08-15 terminal build has a different bundle hash and was not used. |

## SS-078

| Field | Value |
|---|---|
| Filename | `screenshots/SS-078-backend-health.png` |
| Phase | 0 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | freeze-health |
| What is visible | Live `GET /health` JSON: healthy, database connected, HTTP 200 |
| Academic purpose | Runtime process + DB connectivity without credentials |
| Suggested thesis location | Appendix — startup |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No credentials or tokens |
| Evidence source | Live `http://127.0.0.1:8000/health` via Playwright CLI viewport 1920×1080 |

## SS-079

| Field | Value |
|---|---|
| Filename | `screenshots/SS-079-real-user-workflow-start.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | real-user-login-start |
| What is visible | Full login layout: form (left) and DFS investigation panel (right); empty fields; no password |
| Academic purpose | Start of whole-project real-user runtime |
| Suggested thesis location | Appendix — runtime walkthrough |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Empty credentials; sample incident uses masked values only |
| Evidence source | Playwright CLI `resize 1920 1080` + `--hires` screenshot of `http://127.0.0.1:5173/login` |

---

## PHASE 1 — WHOLE-PROJECT REAL-USER RUNTIME

```text
FULL PROJECT RUNTIME VERIFIED
Application SHA: 8b22b670a82b61882cb841b10a9f4d364de30bc7
Hygiene snapshot: e7ca04b7ec517827a783f751fec28036f67d8762
Runtime DB: privacytrace_np_037_verify (127.0.0.1:5432)
Incident: INC-LIVE-E178AEC313
Status: fixed
Report: report_ready=true (label Final report ready)
Application behaviour changes this phase: 0
```

Authoritative path: UI login → Live Monitor ingest → incident → evidence/provenance → RCA → Human Review → remediation → implementation → approved test → controlled retest → verification → report. Backend restart against the same DB left the incident `fixed` and report ready. Browser refresh kept the report page hydrated (SS-059). Viewer RBAC: authorised incident list (SS-052); `/users` denied in UI and `GET /users` HTTP 403 (SS-053). Human-gate: Verify Fix blocked before RCA/review (SS-054). No `ptig_` plaintext, passwords, or raw PII in screenshots.

Category C (recorded, not fixed): load-sample evidence `EVD-S1-*` linked to missing `INC-SEED-001`; report sidebar next-action still “Add Retest Evidence” after report ready; live RCA cause is `unsafe_request_body_logging` (synthetic body leak), not the gold-standard header-logging SAST fixture.

## SS-001

| Field | Value |
|---|---|
| Filename | `screenshots/SS-001-dashboard.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Admin dashboard / privacy operations after real login |
| Academic purpose | Whole-project runtime start after authentication |
| Suggested thesis location | Main — runtime walkthrough |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No passwords or tokens |
| Evidence source | Playwright CLI 1920×1080 `--hires` after admin login |

## SS-002

| Field | Value |
|---|---|
| Filename | `screenshots/SS-002-integrations-overview.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Integrations overview; connector catalogue without token plaintext |
| Academic purpose | Integration surface used by the runtime path |
| Suggested thesis location | Appendix — integrations |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No `ptig_` plaintext |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/integrations` |

## SS-010

| Field | Value |
|---|---|
| Filename | `screenshots/SS-010-sensitive-exposure-detected.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | LPA-783E7EB6DA64 / INC-LIVE-E178AEC313 |
| What is visible | Live Monitor alert with detected sensitive types on `/wallet/transfer` |
| Academic purpose | Detection of sensitive exposure in runtime traffic |
| Suggested thesis location | Main — detection |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Values already masked (`98******67`, `wallet_[masked]`, `txn_[masked]`) |
| Evidence source | Playwright CLI 1920×1080 `--hires` Live Monitor |

## SS-011

| Field | Value |
|---|---|
| Filename | `screenshots/SS-011-privacy-safe-masking.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | LPA-783E7EB6DA64 |
| What is visible | Same live-alert view as SS-010; masked phone/wallet/txn only |
| Academic purpose | Privacy-safe display of detected values |
| Suggested thesis location | Appendix — masking (reused viewport) |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw PII; file is a copy of SS-010 (same live-alert frame) |
| Evidence source | SAME SOURCE VIEWPORT AS SS-010 (identical bytes) |

## SS-012

| Field | Value |
|---|---|
| Filename | `screenshots/SS-012-incident-created.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Incident `INC-LIVE-E178AEC313` created from Live Monitor (`wallet-service` `/wallet/transfer`) |
| Academic purpose | Incident creation from runtime detection |
| Suggested thesis location | Main — incident lifecycle |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Masked values only |
| Evidence source | Playwright CLI 1920×1080 `--hires` incident page |

## SS-013

| Field | Value |
|---|---|
| Filename | `screenshots/SS-013-canonical-evidence.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | EVD-S1-* (demo import) / live EVD-LIVE-153A466DFE66 |
| What is visible | Canonical evidence record in the UI |
| Academic purpose | Evidence object used by the investigation chain |
| Suggested thesis location | Main — evidence |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw secrets |
| Evidence source | Playwright CLI 1920×1080 `--hires`. Category C: demo load-sample evidence is linked to missing `INC-SEED-001`; authoritative live evidence id is `EVD-LIVE-153A466DFE66`. |

## SS-015

| Field | Value |
|---|---|
| Filename | `screenshots/SS-015-evidence-provenance.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | EVD-S1-* / INC-LIVE-E178AEC313 |
| What is visible | Provenance metadata for imported/canonical evidence |
| Academic purpose | Source and ingest provenance |
| Suggested thesis location | Appendix — provenance |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No tokens |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-019

| Field | Value |
|---|---|
| Filename | `screenshots/SS-019-rca.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Likely-cause / RCA for the live wallet incident |
| Academic purpose | Root-cause analysis on the authoritative incident |
| Suggested thesis location | Main — RCA |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw PII |
| Evidence source | Playwright CLI 1920×1080 `--hires`. Cause recorded as `unsafe_request_body_logging` (low confidence). |

## SS-023

| Field | Value |
|---|---|
| Filename | `screenshots/SS-023-human-review.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Human review approved for the live incident |
| Academic purpose | Human gate on analysis before remediation/verification |
| Suggested thesis location | Main — human review |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Reviewer notes sanitized |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-027

| Field | Value |
|---|---|
| Filename | `screenshots/SS-027-remediation.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Remediation playbook / actions after review |
| Academic purpose | Remediation recorded without auto-closing the incident |
| Suggested thesis location | Main — remediation |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | Playwright CLI 1920×1080 `--hires`. AI path returned `input_too_large`; deterministic fallback playbook used. |

## SS-033

| Field | Value |
|---|---|
| Filename | `screenshots/SS-033-implementation-record.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | RIM-D358C3097275 |
| What is visible | Implementation record completed for the live incident |
| Academic purpose | Implementation is recorded, not a production deploy |
| Suggested thesis location | Main — implementation |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No credentials |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-038

| Field | Value |
|---|---|
| Filename | `screenshots/SS-038-test-execution.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | RTE-E57D2B73F879 |
| What is visible | Approved test execution `privacy_regression` passed (28 passed) |
| Academic purpose | Controlled test after implementation |
| Suggested thesis location | Appendix — test execution |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-045

| Field | Value |
|---|---|
| Filename | `screenshots/SS-045-verification-lineage.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | CRT-0FF36D5D483F / VRC-E6C4E5B828EF |
| What is visible | Verification lineage: controlled retest completed, verification passed, verified case id |
| Academic purpose | Fix verification linked to retest evidence |
| Suggested thesis location | Main — verification |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw exposure in UI |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-051

| Field | Value |
|---|---|
| Filename | `screenshots/SS-051-audit-trail.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 |
| What is visible | Populated audit log entries for the runtime investigation |
| Academic purpose | Audit trail of human and system actions |
| Suggested thesis location | Appendix — audit |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No passwords or tokens |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/audit-logs` (recaptured after first take showed loading skeletons) |

## SS-052

| Field | Value |
|---|---|
| Filename | `screenshots/SS-052-authorised-rbac-action.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | viewer@privacytrace.local / INC-LIVE-E178AEC313 |
| What is visible | Viewer role can list incidents; `INC-LIVE-E178AEC313` status `fixed`; Users nav hidden |
| Academic purpose | Authorised RBAC read path |
| Suggested thesis location | Appendix — RBAC |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No password; Viewer badge visible |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/incidents` as viewer |

## SS-053

| Field | Value |
|---|---|
| Filename | `screenshots/SS-053-access-denied.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | viewer GET /users |
| What is visible | Direct `/users`: “User management is restricted”; current role Viewer; required organisation admin. Users link absent from nav. |
| Academic purpose | RBAC negative path |
| Suggested thesis location | Appendix — RBAC |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No credentials |
| Evidence source | Playwright CLI 1920×1080 `--hires` plus API `GET /users` HTTP 403 with viewer JWT |

## SS-054

| Field | Value |
|---|---|
| Filename | `screenshots/SS-054-human-gate-blocked.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 Verify Fix before review |
| What is visible | Verify Fix blocked until human review/RCA prerequisites are met |
| Academic purpose | System/AI cannot skip the human gate |
| Suggested thesis location | Main — human gate |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | Playwright CLI 1920×1080 `--hires` captured before RCA/review completed |

## SS-055

| Field | Value |
|---|---|
| Filename | `screenshots/SS-055-final-incident-report.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 report Summary |
| What is visible | Final investigation report; “Final report ready”; lifecycle checklist Complete |
| Academic purpose | Authoritative final report |
| Suggested thesis location | Main — report |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw PII |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/incidents/INC-LIVE-E178AEC313/report` |

## SS-056

| Field | Value |
|---|---|
| Filename | `screenshots/SS-056-report-provenance.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 report Provenance |
| What is visible | Report Provenance tab |
| Academic purpose | Report provenance for the completed incident |
| Suggested thesis location | Appendix — report provenance |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No tokens |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-057

| Field | Value |
|---|---|
| Filename | `screenshots/SS-057-report-verification.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 report Verification |
| What is visible | Report Verification tab |
| Academic purpose | Verification section of the final report |
| Suggested thesis location | Appendix — report verification |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw exposure |
| Evidence source | Playwright CLI 1920×1080 `--hires` |

## SS-059

| Field | Value |
|---|---|
| Filename | `screenshots/SS-059-browser-refresh-hydration.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 refresh |
| What is visible | Same completed report after browser refresh; Final report ready still shown |
| Academic purpose | Client hydration / state persist across refresh |
| Suggested thesis location | Appendix — persistence |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | SAME SOURCE VIEWPORT AS SS-055 (identical bytes) |

## SS-080

| Field | Value |
|---|---|
| Filename | `screenshots/SS-080-real-user-workflow-complete.png` |
| Phase | 1 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | INC-LIVE-E178AEC313 complete |
| What is visible | Completed incident report: `fixed`, Final report ready, all six workflow steps, PDF/ZIP download. Recapture after an invalid `/setup` take caused by a polluted test `DATABASE_URL`. |
| Academic purpose | End of whole-project real-user runtime |
| Suggested thesis location | Appendix — completed workflow (reused viewport) |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No password; Admin User signed in |
| Evidence source | SAME SOURCE VIEWPORT AS SS-055 (identical bytes) |

## SS-060

| Field | Value |
|---|---|
| Filename | `screenshots/SS-060-nepalfin-overview.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` (PrivacyTrace freeze; lab is separate) |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin home |
| What is visible | NepalFin wallet home: NPR 12,500.00, services, recent NPR activity, KYC verified. Footer discloses synthetic lab. |
| Academic purpose | Target DFS application overview |
| Suggested thesis location | Main — NepalFin |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Synthetic name/phone fixtures only; no live customer data |
| Evidence source | Playwright CLI 1920×1080 `--hires` `http://127.0.0.1:8088/` |

## SS-061

| Field | Value |
|---|---|
| Filename | `screenshots/SS-061-nepalfin-auth.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin sign-in |
| What is visible | Sign-in: email prefilled, password empty |
| Academic purpose | Authentication scenario |
| Suggested thesis location | Appendix — NepalFin |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No password shown |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/auth` |

## SS-062

| Field | Value |
|---|---|
| Filename | `screenshots/SS-062-nepalfin-kyc.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin KYC |
| What is visible | Profile & KYC for Ram Shrestha; citizenship fixture; verified |
| Academic purpose | KYC/profile scenario |
| Suggested thesis location | Appendix — NepalFin |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Synthetic identity only |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/kyc` |

## SS-063

| Field | Value |
|---|---|
| Filename | `screenshots/SS-063-nepalfin-wallet.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin send money |
| What is visible | Wallet-to-wallet send form NPR 250 to WALLET-SYN-002 |
| Academic purpose | Wallet/payment scenario |
| Suggested thesis location | Appendix — NepalFin |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Synthetic phone 9800000001 |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/wallet` |

## SS-064

| Field | Value |
|---|---|
| Filename | `screenshots/SS-064-nepalfin-remittance.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin remittance |
| What is visible | Remittance to Sita Shrestha / NEPAL-SYN-001, NPR 1000 |
| Academic purpose | Remittance/beneficiary scenario |
| Suggested thesis location | Appendix — NepalFin |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Synthetic beneficiary |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/remittance` |

## SS-065

| Field | Value |
|---|---|
| Filename | `screenshots/SS-065-nepalfin-merchant.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin merchant |
| What is visible | Bhatbhateni checkout NPR 499; Pay and Refund |
| Academic purpose | Merchant checkout/refund |
| Suggested thesis location | Appendix — NepalFin |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Synthetic merchant order |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/merchant` |

## SS-066

| Field | Value |
|---|---|
| Filename | `screenshots/SS-066-nepalfin-unsafe.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin unsafe transfer log |
| What is visible | Payment sent NPR 250; intentional unsafe JSON body log including synthetic mobile |
| Academic purpose | Vulnerable scenario before PrivacyTrace sanitisation |
| Suggested thesis location | Appendix — leak path |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Synthetic phone only |
| Evidence source | Playwright CLI 1920×1080 `--hires` after POST `/api/wallet/transfer` |

## SS-067

| Field | Value |
|---|---|
| Filename | `screenshots/SS-067-nepalfin-evidence.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | EVD-INT-91FA453EE616 |
| What is visible | Evidence Import table includes `nepalfin-wallet` runtime logs `EVD-INT-0B10D39B1556` and `EVD-INT-91FA453EE616`, parsed, no linked incident |
| Academic purpose | NepalFin → Runtime → PrivacyTrace evidence |
| Suggested thesis location | Appendix — NepalFin to PrivacyTrace (reused viewport) |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw phone `9800000001` in evidence JSON; no `ptig_` |
| Evidence source | SAME SOURCE VIEWPORT AS SS-006 (identical bytes) |

## SS-068

| Field | Value |
|---|---|
| Filename | `screenshots/SS-068-nepalfin-live-monitor.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin emit → Live Monitor |
| What is visible | Live Monitor after NepalFin Runtime emit. No new incident was opened; detect-all skipped events with no linked incident. Full RCA → remediation → verification for this emit did not occur. Representative full lifecycle remains Phase 1 `INC-LIVE-E178AEC313`. |
| Academic purpose | Bound: sanitised Runtime traffic does not by itself replay the gold-standard incident workflow |
| Suggested thesis location | Discussion / limitations / Appendix — NepalFin |
| Main body / Appendix | LIMITATION |
| PASS / FAIL / INCONCLUSIVE | INCONCLUSIVE (event ingested; no new RCA cycle) |
| Sensitive information checked | No raw PII in UI |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/live-monitor` |

## SS-069

| Field | Value |
|---|---|
| Filename | `screenshots/SS-069-nepalfin-coverage.png` |
| Phase | 2 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin scenario runner |
| What is visible | Coverage hits for auth, KYC, wallet, remittance, merchant, unsafe, checkout, refund |
| Academic purpose | Scenario runner / coverage summary |
| Suggested thesis location | Appendix — NepalFin coverage |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Hit counts only |
| Evidence source | Playwright CLI 1920×1080 `--hires` `/lab/coverage` after `scenarios/run.py` |

---

## Phase 3 — connectors

Runtime emit proven via NepalFin host lab → PrivacyTrace (`nepalfin-wallet`). ScannerBridge labelled **CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION** (not real external scanner integration). Evidence Import: `EVD-4885374839c5` / provenance `PRV-7584AA11999A4356A193`. Wazuh **NOT AVAILABLE** (no SS-017). GitHub hosted workflow **NOT AVAILABLE** (no SS-018). Application behaviour changes this phase: 0.

## SS-004

| Field | Value |
|---|---|
| Filename | `screenshots/SS-004-cli-runtime-install.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | Runtime CLI install against NepalFin |
| What is visible | INSTALLED / CONFIGURED / RECEIVER VERIFIED; token not shown |
| Academic purpose | Runtime connector installation on the external lab |
| Suggested thesis location | Appendix — connectors |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No `ptig_` plaintext |
| Evidence source | `freeze_logs/ss004.html` (CLI summary; token omitted) |

## SS-005

| Field | Value |
|---|---|
| Filename | `screenshots/SS-005-target-app-layout.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin `app/` layout |
| What is visible | Sibling lab tree with `app/main.py`; not PrivacyTrace `backend/` |
| Academic purpose | Realistic Python target for Runtime namespace install |
| Suggested thesis location | Appendix — connectors |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No secrets |
| Evidence source | `freeze_logs/ss005.html` |

## SS-006

| Field | Value |
|---|---|
| Filename | `screenshots/SS-006-runtime-emit.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | NepalFin Runtime emit |
| What is visible | Evidence Import table with `nepalfin-wallet` runtime logs parsed |
| Academic purpose | Lab → PrivacyTrace ingest |
| Suggested thesis location | Appendix — Runtime |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw phone in UI |
| Evidence source | Playwright CLI `/evidence` after host-lab emit |

## SS-007

| Field | Value |
|---|---|
| Filename | `screenshots/SS-007-connector-identity.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | Token-bound source identity |
| What is visible | Trusted source_system `nepalfin-wallet` on ingested runtime rows |
| Academic purpose | Connector identity is token-bound, not client-declared |
| Suggested thesis location | Appendix — Runtime |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No token plaintext |
| Evidence source | SAME SOURCE VIEWPORT AS SS-006 (identical bytes) |

## SS-008

| Field | Value |
|---|---|
| Filename | `screenshots/SS-008-source-spoof.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | Spoofed Runtime source path |
| What is visible | spoof emit True; 0 rows with `/spoofed/not-authoritative`; trusted name remains `nepalfin-wallet` |
| Academic purpose | Source-spoof protection |
| Suggested thesis location | Appendix — Runtime |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No `ptig_` plaintext |
| Evidence source | `freeze_logs/ss008.html` |

## SS-009

| Field | Value |
|---|---|
| Filename | `screenshots/SS-009-duplicate-event.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | Duplicate client event_id |
| What is visible | First and second emit True; source remains `nepalfin-wallet` |
| Academic purpose | Idempotent Runtime ingest |
| Suggested thesis location | Appendix — Runtime |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No token plaintext |
| Evidence source | `freeze_logs/ss009.html` |

## SS-014

| Field | Value |
|---|---|
| Filename | `screenshots/SS-014-evidence-import.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | Controlled historical log import |
| What is visible | `EVD-4885374839c5` api log from `nepalfin-controlled-import` linked to `INC-LIVE-E178AEC313` |
| Academic purpose | Evidence Import path (upload → validate → import) |
| Suggested thesis location | Appendix — Evidence Import |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw PII in UI |
| Evidence source | Playwright CLI `/evidence` after controlled `.log` upload |

## SS-014B

| Field | Value |
|---|---|
| Filename | `screenshots/SS-014B-evidence-provenance.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | Controlled historical log provenance |
| What is visible | Provenance for `EVD-4885374839c5`: collector `file_ingestion`, `PRV-7584AA11999A4356A193` |
| Academic purpose | Evidence Import provenance companion of SS-014 |
| Suggested thesis location | Appendix — Evidence Import |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | No raw PII |
| Evidence source | `freeze_logs/ss014-provenance.html` |

## SS-016

| Field | Value |
|---|---|
| Filename | `screenshots/SS-016-scanner-import.png` |
| Phase | 3 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | CONTROLLED SCANNER-OUTPUT IMPORT VALIDATION |
| What is visible | ScannerBridge import of generic_secret_scanner sample; masked `pk_test_****_demo`; canonical `EVD-SCN-CA35E2DE1CE0` |
| Academic purpose | Controlled scanner-shaped file → sanitise → canonical evidence. **Not** real external scanner integration |
| Suggested thesis location | Appendix — ScannerBridge |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Masked secret only; no full scanner match |
| Evidence source | Playwright CLI `/scanner-bridge?incident=INC-LIVE-E178AEC313` |

## SS-017

Not captured. Wazuh: **NOT AVAILABLE** this run. Excluded from performance denominators.

## SS-018

Not captured. GitHub hosted workflow: **NOT AVAILABLE** this run. Excluded from performance denominators.

## SS-070

| Field | Value |
|---|---|
| Filename | `screenshots/SS-070-heldout-sealed.png` |
| Phase | 4 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | held_out_80 seal |
| What is visible | 80 cases; inputs vs ground_truth SHA-256; HELD_OUT_80_SHA256; Wazuh/GitHub NOT AVAILABLE cells |
| Academic purpose | Independent held-out pack identity before the single evaluation run |
| Suggested thesis location | Appendix — evaluation protocol |
| Main body / Appendix | APPENDIX |
| PASS / FAIL / INCONCLUSIVE | PASS |
| Sensitive information checked | Hashes and family list only; no ground-truth answers |
| Evidence source | `freeze_logs/ss070.html` from `evaluation/heldout/manifest.json` |

After SS-070: application behaviour is locked. No detector/RCA/application tuning against held-out answers.

## SS-071

| Field | Value |
|---|---|
| Filename | `screenshots/SS-071-heldout-results.png` |
| Phase | 5 |
| Application SHA | `8b22b670a82b61882cb841b10a9f4d364de30bc7` |
| Date/time | 2026-08-17 |
| Scenario/test ID | EVAL-HO80-20260817-1 |
| What is visible | Detection F1 0.975610 (TP40 FP2 FN0); RCA Top-1 20/20; scanner 4/4; Wazuh/GitHub excluded; application fixes 0 |
| Academic purpose | Single held-out scoring pass after outputs existed |
| Suggested thesis location | Main — evaluation results |
| Main body / Appendix | MAIN |
| PASS / FAIL / INCONCLUSIVE | PASS (decision miss HO-021; FPs HO-039, HO-046; not rerun) |
| Sensitive information checked | Aggregate metrics only |
| Evidence source | `freeze_logs/ss071.html` from `evaluation/heldout/outputs/EVAL-HO80-20260817-1.score.json` |

---

## IDs without independent captures

The following catalogue IDs have no PNG. They are not manufactured.

| ID | Status |
|---|---|
| SS-003 | NOT CAPTURED |
| SS-020 | NOT CAPTURED |
| SS-021 | NOT CAPTURED |
| SS-022 | NOT CAPTURED |
| SS-024 | NOT CAPTURED |
| SS-025 | NOT CAPTURED |
| SS-026 | NOT CAPTURED |
| SS-028 | NOT CAPTURED (real AI-provider path not verified) |
| SS-029 | NOT CAPTURED |
| SS-030 | NOT CAPTURED |
| SS-031 | NOT CAPTURED |
| SS-032 | NOT CAPTURED |
| SS-034 | NOT CAPTURED |
| SS-035 | NOT CAPTURED |
| SS-036 | NOT CAPTURED |
| SS-037 | NOT CAPTURED |
| SS-039 | NOT CAPTURED |
| SS-040 | NOT CAPTURED |
| SS-041 | NOT CAPTURED |
| SS-042 | NOT CAPTURED |
| SS-043 | NOT CAPTURED |
| SS-044 | NOT CAPTURED |
| SS-046 | NOT CAPTURED |
| SS-047 | NOT CAPTURED |
| SS-048 | NOT CAPTURED |
| SS-049 | NOT CAPTURED |
| SS-050 | NOT CAPTURED |
| SS-058 | NOT CAPTURED |
| SS-017 | NOT AVAILABLE (Wazuh) |
| SS-018 | NOT AVAILABLE (GitHub hosted workflow) |

---

## MAIN / APPENDIX / OPTIONAL / LIMITATION index

**MAIN (14 unique viewports):** SS-001, SS-010, SS-012, SS-013, SS-019, SS-023, SS-027, SS-033, SS-045, SS-054, SS-055, SS-060, SS-071, SS-078.

**APPENDIX:** SS-002, SS-004, SS-005, SS-006, SS-007 (reused SS-006), SS-008, SS-009, SS-011 (reused SS-010), SS-014, SS-014B, SS-015, SS-016, SS-038, SS-051, SS-052, SS-053, SS-056, SS-057, SS-059 (reused SS-055), SS-061–066, SS-067 (reused SS-006), SS-069, SS-070, SS-072–077, SS-079, SS-080 (reused SS-055).

**LIMITATION:** SS-068 (INCONCLUSIVE NepalFin full-lifecycle).

**OPTIONAL / not taken:** SS-003, SS-017, SS-018, SS-020–022, SS-024–026, SS-028–032, SS-034–037, SS-039–044, SS-046–050, SS-058.

