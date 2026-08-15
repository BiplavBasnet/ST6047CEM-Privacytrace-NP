# PrivacyTrace-NP User Guide

This guide explains how to use PrivacyTrace-NP from login to final report, in
simple language. The same guide is available inside the application under
**Help → User Guide**.

## 1. What PrivacyTrace-NP does

PrivacyTrace-NP is a live privacy monitoring and incident traceability
framework for detecting possible sensitive data exposure in API log/event
streams, masking values, creating privacy alerts, correlating evidence,
ranking likely root causes, supporting human review, verifying fixes, and
exporting privacy-safe reports. It:

- passively ingests copied log/event streams and creates masked privacy alerts;
- imports historical and supporting evidence (log files, scan reports, access
  events) without making upload the primary workflow;
- detects possible sensitive-data exposure and creates masked detections;
- ranks likely root causes with confidence levels based on supporting
  evidence;
- requires human review before any incident is confirmed;
- records recommended remediation actions;
- verifies fixes using retest evidence;
- generates privacy-safe reports (PDF, HTML, JSON, CSV, ZIP);

## 2. What it does not do

- It does **not** prove root cause or assign blame. Rankings are likely
  causes that require human review.
- It does **not** change production code. It records recommended remediation
  actions; teams apply fixes outside the tool.
- It does **not** block or modify API traffic; ingestion is passive.
- It complements existing monitoring platforms and does **not** act as a
  firewall.
- It does **not** guarantee privacy leak prevention.
- It **never** displays, stores or exports raw sensitive values.

## 3. Main workflow

```
Live event stream
  → masked privacy alert
  → create or link incident
  → review overview and traceability
  → add technical supporting evidence when needed
  → complete human review (decision + reason)
  → record remediation action
  → send or import retest evidence
  → run fix verification
  → generate final report
  → closure review (human decision)
```

The **Guided Demo** starts with Live Privacy Monitor. Evidence Import remains
available as a secondary path for historical events and controlled evaluation.
Both paths lead into the same incident workflow.

## 4. Live Privacy Monitor

Used for near-real-time privacy alerting from copied log/event streams.

1. Open **Live Privacy Monitor**.
2. Send a synthetic test event (or receive a live event from an integrated
   forwarder).
3. Open the masked privacy alert.
4. Create or link an incident.
5. Review the live alert timeline, evidence strength, missing evidence and
   suggested next action.

Live alerts are symptom and timeline evidence. They cannot establish a
high-confidence likely cause by themselves. Add CI/CD, deployment, code/config
or scanner evidence before evidence strength can become strong.

## 5. Evidence Import

Used for historical investigation, supporting evidence, thesis demonstration,
retest evidence and repeatable evaluation.

1. Open **Evidence Import**.
2. Load synthetic demo evidence or upload a sanitised supported file.
3. Choose the evidence type and optionally link the evidence to an incident.
4. Parse/normalise, run masked detection and continue through the incident.

## 6. Incident Overview

The first section of an incident answers: what happened, where it happened,
what sensitive data type was detected (always masked), the top likely cause
with its confidence band, what evidence supports it, what evidence is
missing, and the next recommended action.

## 7. Traceability

Shows the trace summary, masked detections, evidence chain timeline,
root-cause ranking with score breakdown, contradicting or weakening evidence,
and missing-evidence suggestions. Advanced tables (evidence roles, evidence
graph) are collapsed under "Show advanced details".

> Root-cause ranking is based on available evidence. It is not proof. Human
> review is required.

## 8. Human Review

Human review is the decision point where a responsible analyst accepts the
likely cause for remediation, requests more evidence, declines a false
positive, or escalates the incident.

The review form requires:

- completing the live alert, masked detection, evidence chain, evidence
  strength, missing evidence, CI/CD, remediation and retest checklist;
- choosing one decision — each option shows the incident status it will set;
- a written decision reason (always required, including declines);
- optionally: evidence IDs relied on, a recommended action, and an assigned
  owner.

Accepting the likely cause does **not** mean the incident is fixed — fix
verification is still required. Every decision is recorded in the audit
trail.

## 9. Remediation Action

PrivacyTrace-NP records what must be changed outside the tool. Typical
actions: update logging middleware, mask query parameters, mask authorization
headers, update redaction rules, review debug logging, review reverse
proxy/APM logging. After applying the fix, send a live retest event or import
fixed log/fixed scan evidence so fix verification can run.

## 10. Fix Verification

Checks whether a live retest event or imported retest evidence supports that
the issue appears resolved.
Possible outcomes, in safe wording:

- "Fix verification passed based on available retest evidence."
- "Fix verification failed because sensitive values still appear in retest
  evidence."
- "Fix verification is inconclusive because retest evidence is missing or
  incomplete."

It never claims permanent or certain remediation.

## 11. Final Report

The final output contains the Live Monitor summary, privacy alert timeline,
alert-to-incident flow, evidence source summary, root-cause evidence strength,
masked detections, supporting evidence, human review decision, remediation
action, fix verification status, limitations and privacy controls.

Formats: **PDF** (recommended for viva and client review), **ZIP** (complete
privacy-safe bundle), HTML, JSON, and an evidence CSV. All exports exclude
raw sensitive values. A readiness checklist on the report section shows which
workflow gates are complete before exporting.

## 12. Roles and permissions

| Role | Can do |
|---|---|
| Admin | Full workflow access, user management |
| Security Analyst | Review incidents, make review decisions, create reports, create incidents from alerts |
| DevSecOps Engineer | Monitor alerts, create/link incidents, record remediation, upload retest evidence |
| Auditor | View incidents, evidence, audit trail and reports (read-only) |
| Developer / Viewer | Restricted view access |

The backend enforces every permission (401 for unauthenticated requests, 403
for wrong roles). The interface also hides actions your role cannot perform
and explains what role would be required.

## 13. Safety and masking

All sensitive values are masked before storage, display, alerting, reporting
and export. Examples of masked forms: `984****567`, `WALLET-NP-****`,
`TXN-NP-2026-****`, `jwt_[masked]`, `bearer_[masked]`, `api_key_[masked]`.
Raw values never appear in dashboards, reports, exports, audit logs, backend
logs or this guide.

## 14. Common errors

| Message | What to do |
|---|---|
| "PrivacyTrace-NP backend is unavailable." | Start Docker/Postgres and the FastAPI server (see README). |
| "You do not have permission for this action." | Sign in with a role that has the named permission. |
| "We could not find this incident." | Return to the incident list. |
| "The report could not be generated." | Try again or check incident evidence. No sensitive values are exposed by errors. |
| "Fix verification is waiting for retest evidence." | Upload retest evidence after the fix is applied. |

## 15. Demo walkthrough (about five minutes)

1. Log in as `analyst@privacytrace.local` (demo password on the login page).
2. On the Dashboard, press **Start Guided Investigation**.
3. Run the steps in order (or **Run Full Analysis**): status check → load
   demo evidence → parse → detect → analyse → explain.
4. On the review step, choose a decision and submit (a written reason is
   part of the incident detail review form).
5. Run fix verification and generate the report.
6. Open the incident from **Incidents**, read the Overview, and walk the
   numbered sections to Closure Review.
7. In the Final Report section, download the **PDF** (recommended) or the
   **ZIP bundle**.

All demo data is synthetic. Do not use real customer data, real secrets, or
production logs.
