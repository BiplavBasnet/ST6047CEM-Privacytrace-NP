# Phase 11.8 — Universal Usability and SIEM/SOC Integration Readiness

## Scope

Makes PrivacyTrace-NP easier for developers, security analysts, DevSecOps engineers, and SOC users to operate, and adds a **vendor-neutral, adapter-based** integration layer for common SIEM/SOC workflows.

PrivacyTrace-NP **complements** SIEM/SOC tools with privacy-preserving incident traceability. It does **not** replace a SIEM and is **not** an officially certified vendor plugin.

## Delivered capabilities

### Usability

1. **Guided Investigation Wizard** (`/wizard`) — ten ordered steps from security status through SOC export, with permissions, safe errors, and optional “Run Full Analysis”.
2. **Dashboard UX** — next recommended action on incident detail, copyable evidence IDs, “What this means” helpers, backend disconnected / permission denied / empty / loading states, toast messages.

### Universal integration

1. **Canonical schema** — `PrivacyTraceIntegrationEvent` (see `integration_schema.py`).
2. **Inbound** — `POST /integrations/events`, `POST /integrations/events/batch` (max 100), safety validation, audit logging, safe evidence metadata (`siem_alert`).
3. **Outbound** — `GET /integrations/incidents/{id}/export?format=…` in seven formats.
4. **Frontend** — Integrations page (`/integrations`) with safe examples and copyable curl.
5. **Documentation** — SOC user guide, universal SIEM guide, format mapping.

### Inbound formats (basic adapter mapping)

- `privacytrace_json` (full)
- `ocsf_json`
- `ecs_json`
- `splunk_hec_json`
- `generic_json`

### Outbound formats (basic adapter mapping)

- `privacytrace_json`
- `ocsf_json`
- `ecs_json`
- `splunk_hec_json`
- `cef_like`
- `leef_like`
- `rfc5424_syslog_like`

## Out of scope

- Phase 12 packaging
- Full SIEM product or per-vendor plugins (Splunk, QRadar, Elastic, Wazuh, Sentinel, ArcSight)
- New detection rules, masking changes, causality scoring changes, LLM logic changes
- STIX/TAXII as primary ingestion (documented as future work)
- OpenTelemetry log mapping (documented as future work unless trivial)
- Machine connector tokens (documented as future work; JWT + RBAC used in Phase 11.8)

## Security preserved

- JWT authentication and RBAC on all integration routes
- No weakening of audit or encryption from Phase 11.6–11.7
- Inbound rejection of raw sensitive values and overclaim phrases
- Outbound exports pass report safety validation; no raw payloads returned from ingest APIs

## Verification

```bash
cd backend
pytest app/tests/test_phase11_8_universal_integration.py -v
pytest app/tests -v

cd frontend
npm test
npm run build
```

Manual: login as security analyst → Investigation Wizard → Integrations → ingest safe event → export incident in each format → confirm viewer cannot ingest/export.
