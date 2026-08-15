# Screenshot Checklist — PrivacyTrace-NP (Report & Viva)

Use after a green `pytest app/tests -v` and successful `scripts/demo_smoke_test.ps1`. Capture at **1920×1080** or higher; crop sensitive UI chrome if needed. **Never** screenshot raw sample log files with unmasked values—use API responses only.

| # | Screenshot name | Purpose | Command / endpoint | What the examiner should notice |
|---|-----------------|---------|-------------------|--------------------------------|
| 1 | `01_docker_postgres_running` | Infrastructure ready | `docker compose ps` (project root) | `privacytrace-np-postgres` healthy / running |
| 2 | `02_pytest_all_passed` | Regression confidence | `cd backend; pytest app/tests -v` | All tests passed (or note skip count if any) |
| 3 | `03_health_ok` | API + DB up | `GET http://127.0.0.1:8000/health` | `"status":"healthy"`, `"database":"connected"` |
| 4 | `04_load_sample_result` | Evidence ingested | `POST /evidence/load-sample` `{"scenario":"scenario_1"}` | Files loaded count; no errors |
| 5 | `05_parsed_events` | Normalization works | `GET /evidence` or DB tool / parse-all response | Parsing status parsed; events created |
| 6 | `06_masked_detections` | Detection + masking | `GET /incidents/INC-SEED-001` or trace detections section | `masked_value` fields only; types listed |
| 7 | `07_incident_trace_overview` | Traceability | `GET /incidents/INC-SEED-001/trace` | Timeline, endpoint, service, disclaimer |
| 8 | `08_root_cause_ranking` | Causality engine | Same trace JSON — `likely_root_causes` | Rank 1: `unsafe_request_body_logging`, high band |
| 9 | `09_missing_evidence` | Honest uncertainty | Trace or incident detail — top cause | `missing_evidence` list when applicable |
| 10 | `10_recommended_fix` | Actionable output | Trace / rank 1 `recommended_fix` | Fix targets logging/redaction, not blame |
| 11 | `11_guarded_llm_explain` | Phase 7 assistant | `POST /incidents/INC-SEED-001/explain` `{"provider":"template"}` | Full structured output; likely-cause wording |
| 12 | `12_llm_report_metadata` | Persistence | `GET /incidents/INC-SEED-001/llm-reports` | `report_id`, `provider_used`, `safety_status`, hash |
| 13 | `13_evidence_ids_visible` | Faithfulness | Zoom explain or trace | `EVD-S1-API-001`, `EVD-S1-SAST-001`, etc. |
| 14 | `14_no_raw_sensitive_values` | Privacy | Same JSON — search or highlight masked tokens | No `9841234567`, no `WALLET-NP-`, no raw JWT |
| 15 | `15_swagger_docs` | API surface (optional) | Browser `http://127.0.0.1:8000/docs` | Explain + trace routes present; no Phase 8 review routes |
| 16 | `16_ollama_fallback_optional` | Optional LLM path | Explain with `"provider":"ollama"` or smoke log | `template` fallback if Ollama off; or `ollama` if local model up |

## Capture tips

- Use **Swagger UI** or **PowerShell** `Invoke-RestMethod` formatted output; redact machine paths if desired.  
- For pytest, capture terminal showing **final summary line** (e.g. `109 passed`).  
- Pair each screenshot with a **one-sentence caption** in the thesis (see `evaluation_plan.md`).  
- Store under `docs/screenshots/` (create folder locally; not required in repo).

## Pre-capture commands (single session)

```powershell
.\scripts\demo_reset.ps1
# Terminal 2:
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
# Terminal 1:
.\scripts\demo_smoke_test.ps1
```
