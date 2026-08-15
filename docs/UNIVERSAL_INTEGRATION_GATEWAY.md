# Universal Integration Gateway

## Purpose

The Universal Integration Gateway provides one privacy-safe ingestion boundary
for applications, log forwarders, CI/CD systems, scanner outputs, webhooks, and
alerting tools. It is integration-ready, but environment-specific forwarding,
network, authentication, and field mapping configuration may still be needed.

PrivacyTrace-NP complements existing monitoring platforms. It does not replace
their collection, retention, search, or response capabilities.

## Endpoint flow

External source -> POST /integrations/events -> normalise -> detect and mask ->
privacy alert -> incident creation or linking -> supporting evidence -> human
review -> fix verification -> final report.

Ingestion is passive. PrivacyTrace-NP does not block or modify application
traffic.

## Five-minute setup

1. Start PostgreSQL, apply migrations, and start PrivacyTrace-NP.
2. Start Live Privacy Monitor.
3. Open Integrations and create an integration token.
4. Store the token in the sender's secret manager or environment.
5. Send the synthetic event below (Direct Event Gateway).
   Runtime, Wazuh and GitHub Actions connectors use
   `POST /integrations/connector/v1/events` instead — see Integrations → Connectors.
6. Review the masked result in Live Privacy Monitor.

## Universal event

Required:

- source_name
- message, or a supported structured vendor payload

source_type may be supplied or safely inferred. Unknown values become custom.

Optional:

- source_type
- source_format
- service_name
- endpoint
- environment
- event_time
- severity
- metadata

Accepted source types include api_log, application_log, syslog, siem_alert,
webhook_alert, transaction_event, cicd_event, deployment_event,
scanner_finding, retest_event, and custom.

~~~json
{
  "source_name": "wallet-service",
  "source_type": "api_log",
  "source_format": "generic_json",
  "environment": "staging",
  "service_name": "wallet-service",
  "endpoint": "/wallet/transfer",
  "event_time": "2026-07-13T10:30:00Z",
  "severity": "info",
  "message": "Synthetic integration test event",
  "metadata": {
    "deployment_version": "v1.4.2",
    "trace_id": "trace-demo-001"
  }
}
~~~

## Authentication

Integration tokens have ingestion permission only. They cannot read incidents,
download reports, manage users, or perform administrative actions. Only a
SHA-256 hash is stored. The raw token is shown once at creation and can be
revoked from Integrations.

JWT users with integration:ingest permission remain supported for interactive
testing and backwards compatibility.

## Gateway endpoints

- GET /integrations/status
- GET /integrations/schema
- GET /integrations/snippets
- POST /integrations/events
- POST /integrations/events/batch
- POST /integrations/validate
- POST /integrations/test-event
- POST /integrations/tokens
- GET /integrations/tokens
- DELETE /integrations/tokens/{token_id}

Existing safe export and format endpoints remain available.

## Normalisation and alerts

Every accepted event creates safe EvidenceFile metadata and a NormalizedEvent.
Only a payload hash, masked summary, safe correlation fields, and identifiers
are persisted. Raw request payloads are not persisted.

Events with a possible sensitive exposure create a Live Monitor privacy alert.
Alert details identify the Integration Gateway as the source, display masked
values, list missing metadata, and require human review.

## Correlation metadata

The gateway uses service_name, endpoint, environment, event_time,
deployment_version, trace_id, source_name, and sensitive type. Transaction
references are represented by a hash for correlation. Missing metadata limits
evidence strength and produces explicit recommendations.

## Privacy and safety

- Do not send real customer data during testing without approval and safeguards.
- Do not put integration tokens in source control.
- Raw secrets and customer identifiers are masked before display.
- Unsafe certainty or blame wording is rejected without echoing the input.
- AI receives only existing privacy-safe incident context.
- Alerts do not automatically confirm or close incidents.
- A remediation still requires human review and retest evidence.

## Limitations

- Supported vendor mappings are conservative adapters, not certified plugins.
- The gateway does not collect traffic directly.
- Live Monitor must be running for event ingestion.
- Environment-specific routing and firewall changes may be required.
- In-process event metadata is bounded and resets on restart; durable normalized
  evidence, alerts, audit logs, and token records remain in PostgreSQL.
