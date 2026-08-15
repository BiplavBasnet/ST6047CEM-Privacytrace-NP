# Connector Framework V1

One connector framework so runtime, Wazuh, and GitHub Actions feed the **existing** PrivacyTrace evidence and detection workflow.

```
SOURCE → adapter → safe CloudEvents-inspired event → authenticated receiver
      → privacy gate → normalisation / provenance → existing core
      (Evidence → Alert / Incident → RCA → Review → Remediation → Retest → Verification)
```

The framework **stops** at safe evidence ingestion and provenance. There is no source-specific Incident, RCA, or remediation lifecycle.

This is **not** an OpenTelemetry Collector, not a CloudEvents library integration, and not a second token system.

## User-facing: Integrations

In the product, Connector Framework V1 is discovered from **Integrations** (`/integrations`):
Overview, Connectors, Access Tokens, Developer Setup, Exports.

Implemented connectors: Runtime Connector, Wazuh Adapter, GitHub Actions PoC,
ScannerBridge-NP, Evidence Import.

**Recommended install** is the local CLI `privacytrace-connect` (not published to the
public npm registry). From the PrivacyTrace repository root:

```text
npx --yes --package=file:./connectors/cli privacytrace-connect add runtime
```

Manual file-based setup remains under Integrations → Manual setup. Installation is
not a PyPI / Marketplace product for this prototype.

## Status

| Piece | Status |
|---|---|
| Contract (`docs/contracts/connector-event-v1.json`) | CODE IMPLEMENTED |
| Receiver `POST /integrations/connector/v1/events` | CODE IMPLEMENTED |
| C1 Runtime connector (`connectors/runtime/`) | CODE IMPLEMENTED + installable `privacytrace-runtime` 0.1.0 for the **target app** venv only |
| Connector CLI (`connectors/cli/`) | CODE IMPLEMENTED / local `npx --package=file:./connectors/cli` / public npm NOT PUBLISHED |
| C2 Wazuh adapter (`connectors/wazuh/custom-privacytrace`) | LOCAL WAZUH ADAPTER PATH VERIFIED (synthetic alert file only; not a real Wazuh Manager) |
| C3 GitHub Actions (`connectors/github-actions/`) | CODE IMPLEMENTED / LOCAL CONTRACT VERIFIED / REAL GITHUB-HOSTED WORKFLOW PENDING |
| C4 ScannerBridge-NP | NO CHANGE (existing preview/import path) |
| C5 Evidence Import | NO CHANGE (existing upload path; `source = evidence_import`) |

**Not V1:** Splunk, Elastic, GitLab, Jenkins, IDE plugins, Kubernetes operator, OS agents, universal SDK, custom OTel Collector distro.

## Contract

CloudEvents-inspired JSON envelope: required `specversion` (`1.0`), `id`, `source` (URI-reference, no query/fragment), `type`. Optional `time`, `datacontenttype=application/json`, `data`.

Unknown fields are **forbidden** (`extra=forbid`). That is stricter than CloudEvents 1.0 (which allows extension attributes), so this envelope is **CloudEvents-inspired**, not CloudEvents-compliant.

Finite types:

- `np.privacytrace.runtime.event.v1`
- `np.privacytrace.runtime.exposure.v1`
- `np.privacytrace.wazuh.alert.v1`
- `np.privacytrace.cicd.github.run.v1`

`data` is an allowlist: service, route **template** (not a full URL), method, request_id, trace_id, component, deployment, environment, severity, sensitive_type, masked_value, Wazuh rule id/group/level, GitHub repo/sha/run_id/workflow, bounded `message_summary`.

Maximum size: **64 KiB** (same as Live Monitor / Integration Gateway events). Not the 8 MiB HTTP cap and not the 5 MiB evidence-upload cap.

## Auth

Reuse existing `ptig_` integration tokens. Connector identity is the authenticated token `source_name`. The client cannot spoof identity via `source` or `data.service`. `IntegrationEvent.source_name`, `EvidenceFile.source_system`, and `EvidenceProvenance.source_system` are written from that authenticated identity. Envelope `source` is not persisted as an authoritative field. Revoked tokens (`is_active=False`) are rejected. Human JWTs with `integration:ingest` still work; machine connectors should use tokens.

## Privacy

The new receiver accepts **already-safe** events only.

- **C1 Runtime** (same Python process as the app): local `sensitive_exposure_engine.analyse` runs **per outbound field** before HTTP or queue. If a field is unsafe and cannot be replaced with the engine `masked_preview` in that same field, the event is **dropped** (`privacy_drop`): no POST, no enqueue. `message_summary` may be replaced with a safe summary. Fail-closed.
- **C2 Wazuh / C3 GitHub**: field allowlist only. They never send `full_log`, request bodies, PR titles, or commit messages. Wazuh `alert.location` is omitted (it is not a route template).
- **Receiver gate:** re-scans allowlisted strings with the same engine. Residual secret → `422` with reason `CONNECTOR_PAYLOAD_PRIVACY_REJECTED`. The offending value is never echoed, logged, stored, audited, or sent to AI.

Runtime health is `UNKNOWN` before any send, `AVAILABLE` after a successful POST, `UNAVAILABLE` after timeout or transport failure. Failed sends are stored in a bounded in-memory queue. Queued events can be retried through `flush()`. V1 does not run an automatic background retry worker.

Existing `/integrations/events` and `/live-monitor/events` are unchanged and may still accept raw-then-mask payloads. Do not mix those contracts with this receiver.

## Idempotency and time

Logical identity is `(authenticated source_name, envelope id)`. Partial unique index on `integration_events (source_name, client_event_id)` where both are present. Replay returns `status=duplicate` with the original ids.

Missing `time` → `source_time_quality=inferred`. Extreme skew (>24h vs receive time) → `skewed`. Naive timestamps assumed UTC.

## Existing core constraints

Live Privacy Monitor must be **running** or ingest returns `409`, same as Integration Gateway. The connector does not auto-start the monitor.

ScannerBridge and Evidence Import are **not** routed through this receiver.

## Local proof

Targeted pytest (`test_connector_contract`, `test_connector_adapters`, `test_connector_ingest`): **21 passed** against `privacytrace_np_test`.

- Runtime `emit()` (HTTP stubbed to the app TestClient) created an Evidence row with `evidence_type=runtime_log`.
- Wazuh synthetic alert file → allowlist mapper → receiver created Evidence `siem_alert`. `full_log` and the synthetic phone were not stored or returned.
- GitHub: `node connectors/github-actions/test.js` — **LOCAL CONTRACT VERIFIED**. Sends **CI/CD run and commit provenance** (`repo`, `sha`, `run_id`, `workflow`). **REAL GITHUB-HOSTED WORKFLOW PENDING**. Not build/deployment provenance.

Apply `alembic upgrade head` (revision `037_connector_client_event_id`) on any real database. Tests use `create_all`, not a live Manager or hosted Actions run.
