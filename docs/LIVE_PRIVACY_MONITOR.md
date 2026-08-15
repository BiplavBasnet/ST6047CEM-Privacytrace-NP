# Live Privacy Monitor

## Purpose

Live Privacy Monitor is the primary PrivacyTrace-NP workflow. It passively receives copied log/event data, detects possible sensitive data exposure, masks values before display, creates privacy alerts, and lets analysts link alerts into incident traceability.

Evidence Import remains available as the secondary path for historical logs, supporting evidence, retest evidence, repeatable sample loading and controlled evaluation.

## Fit With PrivacyTrace-NP

Live Monitor feeds the same investigation path already used by the project:

1. Live log/event input
2. Safety validation
3. Detection and masking
4. Privacy alert creation
5. Incident creation or linking
6. Root-cause traceability
7. Technical evidence strengthening when needed
8. Human review
9. Remediation action
10. Live or imported retest evidence
11. Fix verification
12. Safe final report

Alerts are supporting evidence. They do not prove root cause and do not close incidents automatically.

## Evidence Import vs Live Monitor

Evidence Import is the secondary workflow for historical investigation, controlled thesis testing, repeatable scenarios and measured evaluation.

Live Privacy Monitor is the primary workflow for near-real-time alerting from copied log/event streams. It is passive and does not intercept, block, or modify application traffic.

## Passive Ingestion Design

The monitor receives copies of events through HTTP endpoints. External systems can forward logs or event summaries after environment-specific configuration. The backend does not run agents, cloud collectors, Kafka, or other heavy infrastructure for this phase.

## Supported Input Methods

Current supported formats:

- `generic_json`
- `syslog_like`
- `plain_text`
- `api_log_line`
- `ocsf_json`
- `ecs_json`

OCSF/ECS-style support is adapter-based and basic. It requires validation before operational use.

## Detection Engine

`live_monitor_service.process_event` runs the extracted event text (and any
structured payload fields) through the same unified
`sensitive_exposure_engine.analyse()` pipeline used by the Evidence Import
path (see `docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md`), so a given sensitive
value is classified, scored, and masked the same way regardless of which
path observed it. A privacy alert is only created for findings whose
`exposure_decision` is `unsafe_exposure` or `uncertain`; findings the engine
resolves as `legitimate_processing`, `already_safely_masked`, or
`suppressed_false_positive` do not raise an alert. `live_monitor_safety_
service` still runs first as an independent safety gate on raw input size
and unsafe wording, and still asserts the outgoing alert summary is masked,
regardless of what the engine decides.

## Alert Grouping

Repeated occurrences of the same underlying exposure (same sensitive type,
exposure location, service, endpoint, and environment) are grouped onto a
single alert lineage rather than creating a new alert every time — see
`docs/LIVE_ALERT_GROUPING.md`. A grouped alert's `first_seen`, `last_seen`,
and `repeat_count` reflect the real recurrence history, not a placeholder of
"always 1 occurrence."

## API Examples

Start the monitor:

```powershell
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/live-monitor/start `
  -Headers $PrivacyTraceAuthHeader `
  -ContentType "application/json" `
  -Body '{"mode":"http_ingestion","source_name":"wallet-service","environment":"demo","safe_mode":true}'
```

Send a generic event:

```powershell
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/live-monitor/events `
  -Headers $PrivacyTraceAuthHeader `
  -ContentType "application/json" `
  -Body '{"source_type":"api_log","source_name":"wallet-service","source_format":"generic_json","service_name":"wallet-service","endpoint":"/wallet/transfer","environment":"demo","message":"masked live event phone=984****567 wallet=WALLET-NP-****"}'
```

Trigger a synthetic backend-generated test event:

```powershell
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/live-monitor/test-event `
  -Headers $PrivacyTraceAuthHeader
```

List alerts:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/live-monitor/alerts `
  -Headers $PrivacyTraceAuthHeader
```

## Security And Privacy Controls

- Raw event content is not stored.
- Raw event content is not returned through the API.
- `raw_event_hash` is stored for traceability.
- Alert summaries contain masked values only.
- Reports and exports remain masked-only.
- Alert actions are audited.
- Human review is required.
- Unsupported certainty or blame wording is rejected.

## Access Control

The same JWT/RBAC system protects the endpoints.

- View: admin, security analyst, DevSecOps engineer, auditor
- Start/stop: admin, security analyst, DevSecOps engineer
- Ingest: admin, security analyst, DevSecOps engineer
- Create/link incident: admin, security analyst, DevSecOps engineer
- Dismiss: admin, security analyst

Developer and viewer roles do not receive Live Monitor access in this phase.

## Alerts To Incidents

A privacy alert can create a new incident or link to an existing incident. New incidents use `new` status, not a confirmed status. The alert becomes masked supporting evidence and can then appear in traceability views and reports.

## Traceability

When an alert is linked to an incident, PrivacyTrace-NP creates safe evidence metadata, a normalized event with masked summary text, and masked detection rows. The existing incident trace endpoint can then include the live alert evidence.

## Limitations

- Not a replacement for SIEM tools.
- Not a firewall.
- Not guaranteed leak prevention.
- Not universal plug-and-play deployment.
- Requires environment-specific configuration and validation.
- Supports investigation, not blame.
- Alerts are possible privacy exposure signals and require review.
- File-tail mode is not implemented in this phase.
- Alert grouping is exact-match on five dimensions within a fixed 24-hour
  window (`docs/LIVE_ALERT_GROUPING.md`); it does not do fuzzy matching and
  does not itself determine root cause.
- Monitor status (running/stopped, counters, session id) is now persisted to
  the database (`docs/LIVE_CORRELATION_MODEL.md`) so it survives a process
  restart, but a restart still does not replay any events that occurred
  while the monitor process was down.

## Demo Steps

1. Start PostgreSQL and the backend.
2. Login as admin, security analyst, or DevSecOps engineer.
3. Open `Live Privacy Monitor` in the dashboard.
4. Start the monitor.
5. Send the synthetic test event.
6. Confirm a masked alert appears.
7. Create an incident from the alert.
8. Open the linked incident.
9. Generate or export a safe report if required.
10. Confirm raw synthetic values are not displayed.

## Production Deployment Cautions

Before operational deployment, validate log source configuration, authentication, TLS, retention policy, alert routing, access control, privacy/legal requirements, and monitoring limits. Do not forward real customer data unless the deployment has been reviewed and approved for that environment.

