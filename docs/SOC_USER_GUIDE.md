# SOC User Guide — PrivacyTrace-NP

This guide is for security analysts, DevSecOps engineers, and auditors using the PrivacyTrace-NP dashboard. The system ranks **likely** technical causes; it does not assign blame or auto-close incidents.

## 1. Login

1. Open the frontend (default `http://localhost:5173`).
2. Sign in with your assigned account (demo: `analyst@privacytrace.local` / `AnalystPass123!`).
3. If login fails, confirm the backend is running and database is migrated.

## 2. Open the dashboard

- **Incidents** — list and open incident detail.
- **Evidence** — upload or load sample evidence (role permitting).
- **Metrics** — evaluation metrics for demo scenarios.
- **Security** — NIST-aligned crypto profile (read-only for most roles).
- **Investigation Wizard** — guided end-to-end workflow.
- **Integrations** — SIEM/SOC ingest and export (role permitting).

## 3. Use the Investigation Wizard

Navigate to **Investigation Wizard** (`/wizard`).

Recommended order:

1. **Backend / security status** — confirm API and crypto profile are healthy.
2. **Evidence** — load sample or upload evidence for the incident.
3. **Parse** — normalize evidence into events.
4. **Detect** — run sensitive-data detection (masked values only).
5. **Analyse** — rank likely root causes with confidence bands.
6. **Explain** — generate guarded, masked explanation.
7. **Review** — submit human review (required before closure).
8. **Verify fix** — run fix verification against masked detections.
9. **Report** — generate masked incident report.
10. **SOC export** — link to Integrations for safe export.

Use **Run Full Analysis** only when each step’s permission is granted; the wizard stops on the first failure and shows a **safe** error message (no raw API bodies).

## 4. Add evidence or receive a SIEM event

**Manual evidence:** Evidence page → upload or load sample.

**SIEM ingest:** Integrations page → copy the safe `privacytrace_json` example → `POST /integrations/events` with a JWT for a role that has `integration:ingest`. Only **masked** values are accepted.

## 5. Run analysis

From the wizard or incident detail **next recommended action**:

- Run detection if no masked findings exist.
- Run causality analysis if no root-cause scores exist.
- Generate explanation, review, fix verification, and report in order.

## 6. Review likely cause

On incident detail:

- Read **likely root cause** and **confidence band** (not “proven cause”).
- Check **missing evidence** and **evidence completeness** panels.
- Use **Why this cause** for supporting evidence IDs (masked).

## 7. Verify fix

Run fix verification after human review. Status appears on incident detail and in SOC exports.

## 8. Export SOC summary

**Integrations** → select incident → choose format → **Export** → copy safe preview.

Supported outbound formats: PrivacyTrace JSON, OCSF-style, ECS-style, Splunk HEC-style, CEF-like, LEEF-like, RFC5424 syslog-like.

Requires `integration:export` (security analyst, DevSecOps, auditor, admin).

## 9. Role capabilities

| Role | Typical access |
|------|----------------|
| Admin | Full workflow + user management + integration ingest/export |
| Security analyst | Full investigation + ingest/export |
| DevSecOps engineer | Evidence, workflow, fix verify, report, ingest/export |
| Auditor | Read incidents, export SOC summaries, metrics |
| Developer | Read incidents and integration docs (no ingest/export) |
| Viewer | Read incidents and integration format list only |

## 10. Permission denied

If a button is hidden or an API returns 403:

- Your role lacks the required permission (shown in wizard step cards).
- Ask an admin to adjust role assignment, or sign in with an appropriate account.
- The backend always enforces permissions even if the UI hides controls.

## Troubleshooting

- **Backend disconnected** — start API (`uvicorn`), check `VITE_API_BASE_URL`.
- **Empty incidents** — run database seed / Phase 2 seed data.
- **Ingest rejected** — payload likely contains raw sensitive data or overclaim text; use masked values only.
