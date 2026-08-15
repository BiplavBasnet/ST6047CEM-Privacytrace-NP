# Universal SIEM Integration Guide — PrivacyTrace-NP

PrivacyTrace-NP provides an **adapter-based, integration-ready** HTTP layer for forwarding **safe/masked** events into the framework and exporting **safe incident summaries** to SOC dashboards and ticketing tools.

This is **not** a SIEM replacement and **not** official certified integration with Splunk, Elastic, QRadar, Microsoft Sentinel, Wazuh, or ArcSight.

## Architecture

```
External SIEM/SOC tool
        │  safe/masked JSON
        ▼
POST /integrations/events  ──► validation ──► canonical event ──► evidence metadata + audit
        │
        ▼
PrivacyTrace workflow (parse → detect → analyse → review → report)

GET /integrations/incidents/{id}/export?format=…  ◄── safe masked summary
        │
        ▼
SOC dashboard / ticket / forwarder
```

## Authentication and RBAC

All integration routes require `Authorization: Bearer <JWT>` from `/auth/login`.

| Permission | Routes |
|------------|--------|
| `integration:ingest` | `POST /integrations/events`, `POST /integrations/events/batch` |
| `integration:export` | `GET /integrations/incidents/{id}/export` |
| `integration:read` | `GET /integrations/formats`, `GET /integrations/events/{id}`, per-incident formats |

Roles with ingest: **admin**, **security_analyst**, **devsecops_engineer**.  
Roles with export: above plus **auditor**.  
**Viewer** may list formats only.

## Inbound — single event

**Endpoint:** `POST /integrations/events`

**Example (`privacytrace_json`):**

```json
{
  "source_tool": "generic_siem",
  "source_format": "privacytrace_json",
  "external_alert_id": "ALERT-001",
  "event_time": "2026-05-19T10:00:00Z",
  "service_name": "wallet-service",
  "endpoint": "/wallet/transfer",
  "event_type": "sensitive_data_exposure",
  "sensitive_type": "nepali_phone_number",
  "masked_value": "98******67",
  "severity": "high",
  "confidence": 0.95,
  "message": "Masked sensitive value detected in application programming interface log",
  "evidence_reference": "siem-alert-001"
}
```

**Supported `source_format` values:**

- `privacytrace_json` — canonical fields on the request body
- `ocsf_json` — vendor payload in `payload` (basic OCSF mapping)
- `ecs_json` — Elastic Common Schema in `payload`
- `splunk_hec_json` — HEC wrapper in `payload`
- `generic_json` — flat JSON with canonical field names

Unsupported formats return **400** with a clear message.

**Success (200):** `status: accepted`, `integration_event_id`, safe `event` metadata (no raw payload).

**Rejection (422):** `status: rejected`, generic `reason` (unsafe value is **not** echoed).

## Inbound — batch

**Endpoint:** `POST /integrations/events/batch`

```json
{
  "events": [ { "...": "..." }, { "...": "..." } ]
}
```

- Maximum **100** events per request.
- Per-item status in `results[]`; unsafe items are rejected without hiding failures.
- Batch ingestion is audited (`integration_batch_ingested`).

## Inbound — read metadata

**Endpoint:** `GET /integrations/events/{integration_event_id}`

Returns safe canonical fields and `raw_payload_hash` only — **never** the raw payload.

## Outbound — export

**Endpoint:** `GET /integrations/incidents/{incident_id}/export?format={format}`

**Formats:**

| format | content_type |
|--------|----------------|
| `privacytrace_json` | application/json |
| `ocsf_json` | application/json |
| `ecs_json` | application/json |
| `splunk_hec_json` | application/json |
| `cef_like` | text/plain |
| `leef_like` | text/plain |
| `rfc5424_syslog_like` | text/plain |

**List formats:** `GET /integrations/formats` or `GET /integrations/incidents/{id}/formats`

Exports include: incident ID, status, severity, service/endpoint, masked detections, evidence IDs, likely cause ranking, confidence band, missing evidence, human review status, fix verification status, report reference, generated timestamp.

Exports exclude: raw logs, raw sensitive values, JWTs, bearer tokens, API keys, passwords, private keys, decrypted payloads, overclaim phrases.

## Sample curl — ingest

```bash
curl -sS -X POST http://localhost:8000/integrations/events \
  -H "Authorization: Bearer $PRIVACYTRACE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_tool": "generic_siem",
    "source_format": "privacytrace_json",
    "external_alert_id": "ALERT-001",
    "event_time": "2026-05-19T10:00:00Z",
    "service_name": "wallet-service",
    "endpoint": "/wallet/transfer",
    "event_type": "sensitive_data_exposure",
    "sensitive_type": "nepali_phone_number",
    "masked_value": "98******67",
    "severity": "high",
    "confidence": 0.95,
    "message": "Masked sensitive value detected in application programming interface log",
    "evidence_reference": "siem-alert-001"
  }'
```

## Sample curl — export

```bash
curl -sS "http://localhost:8000/integrations/incidents/INC-SEED-001/export?format=ocsf_json" \
  -H "Authorization: Bearer $PRIVACYTRACE_TOKEN"
```

## Safety rules

Inbound validation rejects:

- Raw Nepali phone numbers, wallet IDs, JWTs, bearer tokens, API keys
- Password fields, password hashes, private key blocks, session tokens in cleartext
- Overclaim phrases (e.g. “proven cause”, “developer fault”, “incident closed automatically”)

Rejections are audited (`integration_event_rejected`) with violation codes only.

## Connector tokens (future work)

Phase 11.8 uses **JWT** for integration APIs. Machine **connector tokens** (`integration:ingest`, `integration:export` scopes, hash-only storage) are documented for a future phase to avoid destabilising auth.

## Limitations

- Adapter-based mapping — not every vendor field is preserved.
- No raw log forwarding through this API.
- No automatic incident closure.
- No vendor deployment packages or certified connectors.
- STIX/TAXII and OpenTelemetry mappings are future work.

## Related docs

- [INTEGRATION_FORMAT_MAPPING.md](./INTEGRATION_FORMAT_MAPPING.md)
- [SOC_USER_GUIDE.md](./SOC_USER_GUIDE.md)
- [PHASE11_8_USABILITY_AND_UNIVERSAL_SIEM_READINESS.md](./PHASE11_8_USABILITY_AND_UNIVERSAL_SIEM_READINESS.md)
