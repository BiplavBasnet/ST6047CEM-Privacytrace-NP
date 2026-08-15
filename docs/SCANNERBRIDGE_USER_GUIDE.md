# ScannerBridge-NP — Operator Guide

## Who can do what

| Role | Import | Read / correlate |
|------|--------|------------------|
| Admin | Yes | Yes |
| Security Analyst | Yes | Yes |
| DevSecOps Engineer | Yes | Yes |
| Developer | No | Yes |
| Auditor | No | Yes |
| Viewer | No | No (use incident detail link with `incident:read` for incident-scoped list) |

## Workflow

### 1. Prepare scanner output

Export findings from your external scanner. **Remove or redact** raw secrets before upload. Only masked values (e.g. `pk_****_demo`) should remain.

### 2. Open ScannerBridge-NP

Navigate to **ScannerBridge-NP** in the main menu, or from an incident page via **External scanner evidence**.

Set the target incident ID (e.g. `INC-SEED-001`).

### 3. Preview

Choose the **source format** that matches your file shape. Paste JSON and click **Preview import**.

- If `import_allowed` is false, fix masking or remove unsafe fields.
- Warnings list rejected findings without echoing unsafe content.

### 4. Import

Click **Import evidence**. On success you receive:

- `import_evidence_id` — batch row in evidence store
- `scanner_evidence_ids` — per-finding records

Duplicate imports of the same payload are skipped (fingerprint + hash).

### 5. Link (optional)

If you imported without an incident, use the API `POST /scanner-bridge/evidence/{id}/link` or re-import with `linked_incident_id`.

### 6. Correlate

Click **Run correlation** to rank findings as **supporting evidence** against the incident’s service and endpoint.

Always treat output as advisory — `human_review_required` is always true.

## Safety reminders

- Never paste raw phone numbers, JWTs, API keys, or passwords.
- Avoid overclaim language (“proven cause”, “confirmed blame”).
- ScannerBridge-NP never shows full scanner dumps in the UI or API.
