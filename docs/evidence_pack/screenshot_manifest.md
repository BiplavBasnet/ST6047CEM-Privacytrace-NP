# Thesis Screenshot Manifest (Phase 10)

For each item: capture a **screenshot** (or terminal/API output saved in `api_outputs/`) and store under `docs/evidence_pack/screenshots/` with the filename shown.

---

## 1. Docker PostgreSQL running

| Field | Value |
|-------|--------|
| **Screenshot name** | `01_docker_postgres_running.png` |
| **Command** | `docker compose ps` or Docker Desktop showing `postgres` healthy |
| **Purpose** | Shows reproducible database backing the prototype |
| **Examiner should notice** | Container is up; port 5432 mapped; no ad-hoc SQLite-only demo |

---

## 2. Full pytest result

| Field | Value |
|-------|--------|
| **Screenshot name** | `02_full_pytest_pass.png` |
| **Command** | `cd backend && pytest app/tests -v` |
| **Purpose** | Regression safety for all phases |
| **Examiner should notice** | All tests passed; Phase 10 tests listed |

---

## 3. /health endpoint success

| Field | Value |
|-------|--------|
| **Screenshot name** | `03_health_endpoint.png` |
| **Endpoint** | `GET http://127.0.0.1:8000/health` |
| **Purpose** | API availability before workflow demo |
| **Examiner should notice** | `status: ok` (or equivalent); no stack traces |

---

## 4. Sample evidence loaded

| Field | Value |
|-------|--------|
| **Screenshot name** | `04_sample_evidence_loaded.png` |
| **Endpoint** | `GET /incidents/INC-SEED-001/evidence` |
| **Purpose** | Evidence ingestion for Scenario 1 |
| **Examiner should notice** | Multiple evidence types; masked or safe values only |

---

## 5. Normalised events parsed

| Field | Value |
|-------|--------|
| **Screenshot name** | `05_normalised_events.png` |
| **Endpoint** | `GET /incidents/INC-SEED-001/events` (or trace/events as per API) |
| **Purpose** | Structured timeline from raw logs |
| **Examiner should notice** | Events linked to incident; no raw phone/wallet/API key |

---

## 6. Masked detections

| Field | Value |
|-------|--------|
| **Screenshot name** | `06_masked_detections.png` |
| **Endpoint** | `GET /incidents/INC-SEED-001/detections` |
| **Purpose** | Sensitive data found with masking |
| **Examiner should notice** | Masked phone/wallet/key patterns; severity labels |

---

## 7. Incident trace

| Field | Value |
|-------|--------|
| **Screenshot name** | `07_incident_trace.png` |
| **Endpoint** | `GET /incidents/INC-SEED-001/trace` |
| **Purpose** | End-to-end traceability chain |
| **Examiner should notice** | Evidence IDs and steps; privacy-safe fields |

---

## 8. Root-cause ranking

| Field | Value |
|-------|--------|
| **Screenshot name** | `08_root_cause_ranking.png` |
| **Endpoint** | `GET /incidents/INC-SEED-001/causality` (or root-causes) |
| **Purpose** | Privacy Causality Engine output |
| **Examiner should notice** | Ranked likely causes; confidence band; supporting evidence IDs |

---

## 9. Guarded LLM explanation

| Field | Value |
|-------|--------|
| **Screenshot name** | `09_guarded_llm_explanation.png` |
| **Endpoint** | `POST /incidents/INC-SEED-001/explain` and/or `GET .../llm-reports` |
| **Purpose** | Local Ollama with safety guardrails |
| **Examiner should notice** | Hedged language; evidence IDs; no raw secrets; no “proven cause” |

---

## 10. Human review decision

| Field | Value |
|-------|--------|
| **Screenshot name** | `10_human_review.png` |
| **Endpoint** | `GET /incidents/INC-SEED-001/reviews` |
| **Purpose** | Human-in-the-loop before fix verification |
| **Examiner should notice** | Review status recorded; not auto-closed |

---

## 11. Sanitised audit log

| Field | Value |
|-------|--------|
| **Screenshot name** | `11_audit_log.png` |
| **Endpoint** | `GET /audit/logs` (or incident-scoped audit) |
| **Purpose** | Accountability without leaking secrets |
| **Examiner should notice** | Action types and timestamps; details masked |

---

## 12. Fix verification blocked before review

| Field | Value |
|-------|--------|
| **Screenshot name** | `12_verify_blocked_before_review.png` |
| **Endpoint** | `POST /incidents/INC-SEED-001/verify-fix` (before review approved) |
| **Purpose** | Gate enforces review-first policy |
| **Examiner should notice** | 4xx with clear message; status not “passed” |

---

## 13. Fix verification passed (clean retest)

| Field | Value |
|-------|--------|
| **Screenshot name** | `13_verify_passed_clean_retest.png` |
| **Endpoint** | `POST /incidents/INC-SEED-001/verify-fix` with clean retest evidence |
| **Purpose** | Successful remediation check |
| **Examiner should notice** | `passed` or equivalent; cites retest evidence; no overclaim |

---

## 14. Fix verification failed (unsafe retest)

| Field | Value |
|-------|--------|
| **Screenshot name** | `14_verify_failed_unsafe_retest.png` |
| **Endpoint** | `POST /incidents/INC-SEED-001/verify-fix` with unsafe retest sample |
| **Purpose** | System detects lingering exposure |
| **Examiner should notice** | `failed`; still masked output; incident not auto-closed |

---

## 15. JSON report output

| Field | Value |
|-------|--------|
| **Screenshot name** | `15_json_report.png` |
| **Endpoint** | `POST /reports/incidents/INC-SEED-001/generate` body `{"report_type":"json","requested_by":1}` |
| **Purpose** | Machine-readable incident report |
| **Examiner should notice** | Full sections; evidence IDs; no raw sensitive values |

---

## 16. HTML report output

| Field | Value |
|-------|--------|
| **Screenshot name** | `16_html_report.png` |
| **Endpoint** | `POST /reports/incidents/INC-SEED-001/generate` body `{"report_type":"html","requested_by":1}` |
| **Purpose** | Human-readable report without dashboard UI |
| **Examiner should notice** | Escaped HTML; safety statement; same content as JSON |

---

## 17. Evaluation metrics output

| Field | Value |
|-------|--------|
| **Screenshot name** | `17_evaluation_metrics.png` |
| **Endpoint** | `GET /metrics/evaluation` after `POST /metrics/evaluation/run` |
| **Purpose** | Thesis-aligned metrics |
| **Examiner should notice** | Each metric has `thesis_claim` and `calculation_method`; includes TTCL |

---

## 18. No raw sensitive values shown

| Field | Value |
|-------|--------|
| **Screenshot name** | `18_no_raw_sensitive_values.png` |
| **Command** | Output of `.\scripts\capture_phase10_evidence.ps1` showing PASS |
| **Purpose** | Automated leak scan across saved artifacts |
| **Examiner should notice** | PASS for blocked-value and overclaim scans |
