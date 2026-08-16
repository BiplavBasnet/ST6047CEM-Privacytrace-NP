# Phase 11 — PrivacyTrace-NP React Dashboard

## Included

- React + Vite + TypeScript + Tailwind dashboard under `frontend/`
- Routes: Home, Incidents, Incident Detail, Evidence (metadata only), Reports, Metrics
- API client targeting `http://127.0.0.1:8000`
- Display-time safety utility (`src/utils/safety.ts`) blocking raw seed values and overclaim phrases
- Vitest unit/component tests
- Minimal CORS on FastAPI for `http://127.0.0.1:5173` and `http://localhost:5173` only

## Excluded

- Phase 12 deployment / production hardening
- Authentication, dark theme, advanced SOC UI
- Backend detection, masking, causality, LLM, review, fix verification, or report/metrics logic changes
- New scanners, cloud LLM, fine-tuning
- Raw evidence file contents in the UI

## Backend endpoints used

| Method | Path |
|--------|------|
| GET | `/health` |
| GET | `/incidents` |
| GET | `/incidents/{incident_id}` |
| GET | `/incidents/{incident_id}/trace` |
| GET | `/incidents/{incident_id}/llm-reports` |
| GET | `/incidents/{incident_id}/reviews` |
| GET | `/audit-logs?incident_id=` |
| GET | `/incidents/{incident_id}/fix-verifications` |
| GET | `/evidence` |
| GET | `/evidence/{evidence_id}` |
| POST | `/reports/incidents/{incident_id}/generate` |
| GET | `/reports/incidents/{incident_id}` |
| GET | `/metrics/evaluation` |
| POST | `/metrics/evaluation/run` |

## Privacy safety rules

- Never render: `9841234567`, `WALLET-NP-88291`, `pk_test_np_fake_12345`, JWTs, bearer tokens, or overclaim phrases
- Fallbacks: `[blocked sensitive value]`, `[blocked unsafe claim]`
- Evidence view: metadata fields only (no file body)
- Incident detail: `masked_value` only from trace timeline
- HTML reports: sandboxed iframe + sanitized `srcDoc`
- No `console.log` of API payloads

## Five-minute demo walkthrough

1. Start backend (see below) after Phase 10 workflow prep (`scripts/phase10_prepare_workflow.ps1`).
2. Open `http://127.0.0.1:5173` — confirm backend health on Home.
3. Open **Incidents** → `INC-SEED-001`.
4. Review masked detections, evidence IDs, root-cause ranking, guarded explanation, human review, fix verification.
5. **Reports** → generate JSON and HTML for `INC-SEED-001`.
6. **Metrics** → show thesis-aligned evaluation table (optional chart).

## Run backend

```powershell
cd backend
pytest app/tests -v
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Run frontend

```powershell
cd frontend
npm install
npm run dev
```

Dashboard: `http://127.0.0.1:5173`

## Run frontend tests

```powershell
cd frontend
npm test
```

## CORS note

Browsers block cross-origin calls from port 5173 to 8000 without CORS. `backend/app/main.py` adds `CORSMiddleware` for local Vite origins only. This does not change API business logic.
