# Final Test Report

**HISTORICAL / DEVELOPMENT TEST REPORT.** This document is not a current freeze or release gate.

Date: 2026-07-16

Environment: Windows PowerShell, Python 3.13, Node/Vite frontend.

## Results

- Frontend TypeScript: passed with `npx tsc -b --pretty false`.
- Frontend tests: 30 files passed, 116 tests passed with `npm test`.
- Frontend build: passed with `npm run build`; Vite reported a chunk-size warning.
- Focused backend workflow tests: 18 passed with `pytest app/tests/test_workflow_integrity.py -v --tb=short`.
- Backend workflow, integration gateway, live-first, and security regression group: 36 passed.
- ScannerBridge backend group: 26 passed.
- Crypto/NIST backend group: 35 passed when run outside the restricted temp-directory sandbox.
- Full backend suite: attempted; 450 tests passed before timeout/failure. Follow-up focused groups covering the failures above passed after fixes.

## Browser Pages Checked

In-app browser automation was unavailable in this session. Local route and API smoke checks passed for:

- Login
- Dashboard
- Live Monitor
- Alert Queue
- Incidents
- Incident Overview
- Root Cause & Traceability
- Human Review
- Remediation
- Fix Verification
- Final Report
- Integration Hub
- Evidence Import
- Reports
- ScannerBridge-NP

## Failures Found

- Initial frontend test/build failed under sandbox because Vite/Vitest could not spawn esbuild.
- Initial backend pytest import failed because `psycopg2-binary` was not installed in the active Python environment.
- Backend integration gateway used invalid Starlette status constant `HTTP_422_UNPROCESSABLE_CONTENT`.
- ScannerBridge used invalid Starlette status constant `HTTP_413_CONTENT_TOO_LARGE`.

## Fixes Applied

- Installed backend dependencies from `backend/requirements.txt`.
- Re-ran frontend build/tests with permission to spawn required Node workers.
- Replaced invalid 422 constants with `HTTP_422_UNPROCESSABLE_ENTITY`.
- Replaced invalid 413 constants with `HTTP_413_REQUEST_ENTITY_TOO_LARGE`.

## Remaining Failures

No source-level failure is known from the completed focused checks. The full backend suite did not complete cleanly in one run before timeout, and in-app browser automation was not exposed by the available tool surface.