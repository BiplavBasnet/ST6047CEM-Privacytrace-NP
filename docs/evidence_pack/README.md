# PrivacyTrace-NP — Thesis Evidence Pack (Phase 10)

This folder stores **repeatable proof** for the dissertation: test output, safe API responses, and a screenshot checklist. Capture evidence **before** changing sample data or rules so viva/demo material stays consistent.

## Contents

| Item | Purpose |
|------|---------|
| `screenshot_manifest.md` | Required screenshots, endpoints, and what examiners should notice |
| `test_results.txt` | Full `pytest app/tests -v` output (generated) |
| `api_outputs/` | Sanitized JSON from workflow endpoints (generated) |
| `capture_summary.json` | Machine-readable PASS/FAIL summary (generated) |
| `capture_summary.txt` | Human-readable summary (generated) |
| `capture_status.md` | Per-check status table (generated) |

## How to capture (recommended)

1. Clean reset (Docker, migrate, seed):
   ```powershell
   .\scripts\phase10_clean_reset.ps1
   ```
2. Start API (separate terminal):
   ```powershell
   cd backend
   .\.venv\Scripts\Activate.ps1
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
3. Optional: prepare workflow only:
   ```powershell
   .\scripts\phase10_prepare_workflow.ps1
   ```
4. Full capture (pytest + health + workflow + reports + metrics + scans):
   ```powershell
   .\scripts\capture_phase10_evidence.ps1
   ```

Expected final line: **PHASE 10 EVIDENCE CAPTURE: PASS**

The script **fails loudly** if the backend is down, the database is disconnected, API steps fail, or saved files contain forbidden raw sensitive substrings or overclaim phrases.

See also: `docs/phase10_completion_checklist.md`

## Privacy rules

- Never commit real customer data.
- Only synthetic Scenario 1 samples are used.
- If `capture_phase10_evidence.ps1` reports FAIL, fix the pipeline before taking thesis screenshots.

## Related docs

- `docs/evaluation_plan.md` — metric definitions
- `docs/scenario_ground_truth.md` — expected Scenario 1 outcomes
- `docs/baseline_comparison_plan.md` — manual vs scanner vs PrivacyTrace-NP
- `docs/demo_walkthrough.md` — live demo script
