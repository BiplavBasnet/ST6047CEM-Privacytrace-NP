# PrivacyTrace-NP Live-First Guided Demo

## Demo objective

Show that PrivacyTrace-NP passively receives a synthetic API log/event copy,
masks possible sensitive values, creates a privacy alert, links the alert to an
incident, strengthens the likely-cause explanation with evidence, requires
human review, records retest evidence, verifies the fix based on available
evidence, and exports a privacy-safe final report.

PrivacyTrace-NP complements existing monitoring platforms. It does not block
API traffic, establish cause by itself, close incidents automatically, or make
certain remediation claims.

## Prerequisites

- Docker Desktop running.
- Backend virtual environment available at `backend/.venv`.
- Backend running at `http://127.0.0.1:8000`.
- Frontend running at `http://127.0.0.1:5173` (or the port shown by Vite).
- A demo user with Live Monitor, incident, review, verification and report
  permissions.

## Live-first browser sequence

1. Log in and confirm the dashboard health cards are available.
2. Confirm the first workflow panel is **Live Monitor Status**.
3. Open **Live Privacy Monitor**.
4. Select **Send Synthetic Test Event**.
5. Open the new masked privacy alert in the live alert timeline.
6. Create an incident from the alert.
7. Open the incident and confirm the source badge shows **Live Monitor**.
8. Review the live alert timeline, masked detections, evidence chain,
   root-cause evidence strength, missing evidence and confidence limitation.
9. Import CI/CD, deployment, code/config or ScannerBridge evidence when the
   likely-cause explanation needs technical support.
10. Complete the Human Review checklist and record a decision and reason.
11. Record or accept the remediation action outside production execution.
12. Select **Send Live Retest Event**, or import a fixed log/fixed scan on
    **Evidence Import**.
13. Run fix verification after the human-review gate is satisfied.
14. Generate the final report and verify it contains the Live Monitor summary,
    privacy alert timeline, evidence source summary, evidence strength, review,
    remediation, verification and limitations.

## Secondary historical path

Use **Evidence Import** instead when investigating historical events, adding
supporting evidence, importing retest evidence or running controlled thesis
evaluation. Manual upload and synthetic demo evidence remain available. The
imported evidence continues through the same incident workflow.

## Expected evidence-strength behavior

- Live alerts, API logs and alert exports are symptom/timeline evidence.
- Symptom evidence alone remains **weak**, regardless of event count.
- CI/CD, deployment, code/config and scanner evidence provide technical
  support.
- Retest evidence supports fix verification.
- Human review remains required at every strength level.

## Safety checks during the demo

- Dashboards, console messages and exports show masked values only.
- No raw event or raw alert payload is displayed.
- The alert alone is not described as a high-confidence likely cause.
- A passed verification is described as based on available retest evidence.
- Browser Back returns to the previous workflow page.
- Evidence Import, ScannerBridge-NP, final reports and the historical evidence
  workflow remain accessible.

## Troubleshooting

| Symptom | Check |
|---|---|
| Backend unavailable | Start FastAPI and confirm `GET /health` is healthy. |
| Database disconnected | Start PostgreSQL and apply migrations. |
| Action hidden | Use a role with the required backend permission. |
| No alert created | Start ingestion and use the synthetic test event. |
| Verification blocked | Complete an accepted human review and add linked retest evidence. |
| Report unavailable | Confirm the incident exists and the user can generate reports. |

All demo data and integration examples are synthetic. Raw sensitive values
must never be pasted into the browser, screenshots, console or report.
