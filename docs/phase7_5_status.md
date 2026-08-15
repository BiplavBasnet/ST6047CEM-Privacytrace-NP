# Phase 7.5 Status — Evaluation and Demo Pack

## Why Phase 7.5 exists

Phases 1–7 delivered a working privacy-preserving backend (evidence → mask → causality → guarded LLM). Phase 7.5 adds **repeatable proof** for the thesis and viva: evaluation metrics, ground truth, demo scripts, and screenshot guidance—without new product features.

## Files created

| File | Purpose |
|------|---------|
| `docs/evaluation_plan.md` | Metrics, baselines, LLM/privacy evaluation, thesis linkage |
| `docs/scenario_ground_truth.md` | Scenario 1 labelled expectations |
| `docs/screenshot_checklist.md` | Report-ready capture list |
| `docs/demo_walkthrough.md` | 5-minute live demo script |
| `scripts/demo_reset.ps1` | Docker + migrate + seed |
| `scripts/demo_smoke_test.ps1` | End-to-end API validation |
| `docs/phase7_5_status.md` | This summary |

## Commands to run

```powershell
# Terminal 1 — project root
.\scripts\demo_reset.ps1

# Terminal 2 — backend
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 1 — after API is up
.\scripts\demo_smoke_test.ps1

# Regression
cd backend
pytest app/tests -v
```

## What is not included

- Phase 8 human review workflow (approve/reject)  
- Phase 9 fix verification execution  
- Frontend / dashboard  
- Cloud LLM integration  
- Fine-tuning or new detection categories  
- Backend Docker image / containerized FastAPI  

## Phase 8 confirmation

**Phase 8 has not been started.** No review tables, review routes, or review services were added in Phase 7.5.
