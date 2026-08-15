# Gold-Standard Remediation Scenario

Canonical end-to-end fixture for verified remediation evaluation.

## Ground truth

| Field | Value |
|---|---|
| Fixture | `backend/fixtures/gold_standard_wallet/request_logger.py` |
| Function | `log_request_headers` |
| Sensitive type | `bearer_token` |
| Exposure location | `request_header_log` |
| Service | `synthetic-wallet-service` |
| Endpoint | `/wallet/transfer` |
| Root cause | `unsafe_request_header_logging` |
| Component | request logging middleware |
| Synthetic token | `SYNTHETIC_TEST_TOKEN_123` (retest: `SYNTHETIC_RETEST_TOKEN_456`) |

## Vulnerability

Default `redact=False` serialises the Authorization header into the log line before redaction. Synthetic token only — no real credentials.

## Leak mechanism

Controlled request carries `Authorization: Bearer SYNTHETIC_TEST_TOKEN_123` → middleware logs full headers → raw bearer token enters application log.

## Expected detection

- Sensitive type: bearer_token
- Exposure location: request_header_log (or application_log depending on ingest path)
- Unsafe exposure (not legitimate processing)

## Expected root cause / remediation

- Likely cause: `unsafe_request_header_logging`
- Component: request logging middleware
- Remediation: redact or exclude Authorization before logging/serialisation (`redact=True` / `_redact_headers`)

## Expected test / retest / verification

- Profile: `synthetic_request_logger_regression`
- After fix: raw token absent; redacted form may appear; path metadata retained; app still functions
- Retest: same service/endpoint/exposure/sensitive type with new synthetic secret
- Verification wording on pass: “Verification passed based on available controlled retest evidence.”

## Proof path

`backend/app/tests/test_gold_standard_verified_remediation.py`

Flow: SAST source evidence → diagnosis → human edit/accept (`original_ai_payload` preserved) → real unified diff → sandbox apply → regression → verified case → playbook counters → rollback.

## Persistence

Migration `024_verified_remediation_completion`: `verified_remediation_cases`, `remediation_playbooks`, `patch_proposals`.

## Honesty bounds

Synthetic allowlisted sandbox proof — not a production deploy. Interactive browser 45-step sandbox apply was not re-run in this phase; service-level gold test is authoritative for patch → learning.
