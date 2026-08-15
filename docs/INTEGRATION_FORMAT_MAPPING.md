# Integration Format Mapping — PrivacyTrace-NP

This document describes the **canonical** `PrivacyTraceIntegrationEvent` schema and how inbound/outbound adapters map to common SOC/SIEM representations.

Mappings are **basic and adapter-based** — not full vendor specification compliance and **not** certified integrations.

## Canonical schema (`PrivacyTraceIntegrationEvent`)

| Field | Description |
|-------|-------------|
| `schema_version` | e.g. `1.0` |
| `source_tool` | Originating SIEM or forwarder name |
| `source_format` | Inbound adapter used |
| `external_alert_id` | Upstream alert identifier |
| `external_incident_id` | Optional upstream incident ID |
| `event_time` | When the event occurred |
| `received_at` | When PrivacyTrace accepted the event |
| `service_name` | Affected service |
| `endpoint` | Affected API path |
| `environment` | e.g. staging, production |
| `event_type` | e.g. `sensitive_data_exposure` |
| `sensitive_type` | Classification of masked finding |
| `masked_value` | Masked sensitive representation only |
| `severity` | low / medium / high / critical |
| `confidence` | 0.0–1.0 |
| `message` | Safe human-readable summary |
| `evidence_reference` | External or internal evidence ID |
| `source_ip` / `destination_ip` | Optional network context |
| `user_or_actor` | Masked or pseudonymous actor |
| `trace_id` | Correlation ID |
| `tags` | Key:value or free-form tags |
| `raw_payload_hash` | SHA-256 of inbound request (traceability) |
| `safety_status` | `safe` or `rejected` |
| `linked_incident_id` | Optional PrivacyTrace incident |

**Rules:** raw payload is never returned via API; raw sensitive values are rejected at ingest.

---

## Inbound mapping

### `privacytrace_json`

Request body fields map 1:1 to the canonical schema.

### `ocsf_json` (basic)

| OCSF (informal) | Canonical |
|-----------------|-----------|
| `metadata.uid` | `external_alert_id` |
| `severity` | `severity` |
| `time` / `event_time` | `event_time` |
| `service.name` | `service_name` |
| `http_request.url.path` | `endpoint` |
| `message` / `finding.title` | `message` |
| `observables[]` | `tags` / `evidence_reference` |

### `ecs_json` (basic)

| ECS | Canonical |
|-----|-----------|
| `event.id` | `external_alert_id` |
| `@timestamp` | `event_time` |
| `service.name` | `service_name` |
| `url.path` | `endpoint` |
| `event.severity` / `log.level` | `severity` |
| `message` | `message` |
| `labels.*` | `tags` |

### `splunk_hec_json` (basic)

| HEC field | Canonical |
|-----------|-----------|
| `time` (epoch or ISO) | `event_time` |
| `source` / `sourcetype` | tags / metadata |
| `event.{...}` | inner fields mapped to canonical columns |

### `generic_json`

Flat JSON using canonical field names inside `payload`.

---

## Outbound mapping (incident export)

Source: safe incident summary built from masked report content (no raw logs).

### `privacytrace_json`

Full canonical incident summary object (incident_id, masked_detections, root_cause_ranking, review/fix status, etc.).

### `ocsf_json` (basic)

| Canonical | OCSF-style |
|-----------|------------|
| `incident_id` | `metadata.uid` / finding uid |
| `severity` | `severity` |
| `affected_service` | `service.name` / `resources` |
| `affected_endpoint` | `http_request.url.path` |
| `top_likely_cause` | `finding.title` |
| `linked_evidence_ids` | `unmapped.evidence_ids` / observables |
| `confidence_band` | `confidence` |

### `ecs_json` (basic)

| Canonical | ECS |
|-----------|-----|
| `incident_id` | `event.id` |
| `generated_at` | `@timestamp` |
| — | `event.kind` = `alert` |
| — | `event.action` = `privacytrace_sensitive_data_exposure` |
| `affected_service` | `service.name` |
| `affected_endpoint` | `url.path` |
| `severity` | `event.severity` / `log.level` |
| `linked_evidence_ids` | `labels.evidence_ids` |
| `top_likely_cause` | `labels.privacytrace_likely_cause` |
| `confidence_band` | `labels.privacytrace_confidence_band` |

### `splunk_hec_json` (basic)

```json
{
  "time": "<epoch_seconds>",
  "source": "privacytrace-np",
  "sourcetype": "privacytrace:incident",
  "event": { "<safe incident summary>" }
}
```

### `cef_like` (basic string)

```
CEF:0|PrivacyTrace-NP|PrivacyTrace-NP|1.0|privacy_exposure|Sensitive Data Exposure Trace|<severity>|cs1Label=incident_id cs1=<id> cs2Label=likely_cause cs2=<masked cause> ...
```

### `leef_like` (basic string)

```
LEEF:2.0|PrivacyTrace-NP|PrivacyTrace-NP|1.0|privacy_exposure|severity=<sev> incident_id=<id> likely_cause=<masked> ...
```

### `rfc5424_syslog_like` (basic string)

```
<134>1 <timestamp> privacytrace-np PrivacyTrace-NP - ID47 [privacytrace incident_id="<id>" severity="<sev>" service="<svc>"] <safe summary>
```

---

## Future work (not Phase 11.8)

- **STIX/TAXII** — threat-intelligence exchange (document only).
- **OpenTelemetry** — log signal mapping (document only).
- **Connector tokens** — scoped M2M tokens with hash-only storage.
- **Vendor-specific adapters** — optional plugins built on this canonical layer.

---

## Positioning

PrivacyTrace-NP **complements** SIEM/SOC tools by adding privacy-preserving incident traceability with likely-cause ranking and human review. It does **not** replace SIEM tools and is **not** an officially certified vendor plugin.
