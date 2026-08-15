# Phase 11.5 — Differentiation and Demo Hardening

## What was improved

Phase 11.5 adds five frontend-only differentiation panels that make PrivacyTrace-NP easier to explain in a thesis demo:

1. **Causal investigation timeline** — shows investigation stages (evidence → detection → masking → ranking → explanation → review → fix verification → reports → metrics) using existing API data only.
2. **Evidence completeness score** — linked evidence count, available types, missing types, completeness percentage, and confidence impact (frontend calculation).
3. **Why this likely cause** — top ranked cause with supporting evidence IDs, missing evidence, recommended fix, and guarded explanation preview.
4. **Before / after fix verification** — masked “before” detections vs retest evidence and verification checks in the “after” column.
5. **Basic scanner vs PrivacyTrace-NP** — static comparison on the Home page (no invented performance numbers).

## Why this is better than a normal scanner

A typical sensitive-data scanner may alert on a pattern. PrivacyTrace-NP demonstrates an **investigation workflow**: mask values, link evidence IDs, rank **likely** technical causes, surface missing evidence, require human review, verify fixes with retest evidence, and export safe reports plus thesis-aligned metrics.

## Screenshots to capture

1. Home — Basic scanner vs PrivacyTrace-NP comparison.
2. Incident `INC-SEED-001` — causal timeline (all stages available after workflow prep).
3. Evidence completeness panel (percentage and missing types).
4. Why this likely cause panel.
5. Before / after fix verification panel.
6. Masked detections list (no raw values).
7. Reports page — sanitized JSON and sandboxed HTML.
8. Metrics page — thesis claim and calculation method columns.

## Demo script

1. Open dashboard Home.
2. Show Basic Scanner vs PrivacyTrace-NP comparison.
3. Open INC-SEED-001.
4. Show masked detections.
5. Show causal timeline.
6. Show Evidence Completeness Score.
7. Show Why This Cause panel.
8. Show human review.
9. Show Before/After Fix Verification.
10. Show report and metrics.

## Safety rules

- All rendered text passes through `frontend/src/utils/safety.ts`.
- Blocked literals: phone, wallet, test API key, JWT/bearer/authorization patterns.
- Blocked claims: proven cause, confirmed blame, guaranteed cause, definitely caused by, developer fault, guaranteed fixed, incident closed automatically.
- No raw log bodies; evidence page remains metadata-only.
- No `console.log` of API payloads.

## What was not changed

- No new scanners, detection categories, or LLM providers.
- No cloud LLM, fine-tuning, authentication, PDF export, or deployment packaging.
- No Phase 12 documentation overhaul.
- No backend business logic changes (detection, masking, causality, review, fix verification, reports, metrics).

## Run commands

```powershell
# Prepare demo data (with API running after clean reset)
.\scripts\phase10_clean_reset.ps1
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
# separate terminal
.\scripts\phase10_prepare_workflow.ps1

cd frontend
npm run dev
```

```powershell
cd frontend
npm test

cd ..\backend
pytest app/tests -v
```
