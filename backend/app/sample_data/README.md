# Scenario 1 — Synthetic Sample Evidence

**Synthetic data only.** No real customer data, secrets, tokens, or company names.
All values are synthetic and created only for thesis demonstration. Do not use real customer logs, real API keys, real wallet data, or production evidence.

## Story

Sensitive data appears in **wallet transfer API logs** after a **deployment** with **DEBUG logging** enabled. Supporting evidence includes **unsafe request-body logging** (Semgrep), a **fake secret** finding (Gitleaks-style), a **failed access** event, and **weak dependency** evidence (Trivy-style). **Retest** logs show redacted metadata after remediation.

## Expected likely causes (Phase 6+)

1. `unsafe_request_body_logging` (primary)
2. `debug_logging_enabled` (secondary)
3. `suspicious_dependency_introduced` (weak supporting only)

## Files

| Path | evidence_type | evidence_id |
|------|---------------|-------------|
| `logs/wallet_transfer_api.log` | api_log | EVD-S1-API-001 |
| `logs/wallet_runtime.log` | runtime_log | EVD-S1-RT-001 |
| `scans/semgrep_wallet_logging.json` | semgrep_report | EVD-S1-SAST-001 |
| `scans/gitleaks_wallet_secret.json` | gitleaks_report | EVD-S1-SECRET-001 |
| `deployments/wallet_deploy_debug.json` | deployment_log | EVD-S1-DEPLOY-001 |
| `access_events/wallet_access_denied.json` | access_event | EVD-S1-ACCESS-001 |
| `dependency_findings/trivy_wallet_dep.json` | trivy_report | EVD-S1-TRIVY-001 |
| `retest_evidence/wallet_transfer_retest.log` | fixed_log | EVD-S1-FIXED-001 |

Suggested linked incident: `INC-SEED-001` (Phase 2 seed) or `INC-SCENARIO-001`.
