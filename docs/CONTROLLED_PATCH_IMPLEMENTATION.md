# Controlled Patch Implementation

How PrivacyTrace-NP turns an accepted remediation into a real unified diff — without touching production.

## Scope

- Service: `controlled_patch_service`
- Storage: `patch_proposals` (migration `024_verified_remediation_completion`)
- Gold target: `fixtures/gold_standard_wallet/request_logger.py` → `log_request_headers`

## Preconditions

1. Human-accepted diagnosis with exact source location established.
2. Repository path on `REMEDIATION_REPO_ALLOWLIST`.

This path is an **Allowlisted Controlled Patch PoC**, limited to the documented
gold fixture. Before apply it verifies the exact affected file, base-content hash,
persisted diff hash, and canonical diff. After apply it verifies the resulting
content hash. Rollback requires both an unchanged post-apply hash and an original
snapshot matching the approved base; drift enters `recovery_required` and fails closed.
3. Reject / more-evidence states do **not** unlock patch generation.

## Lifecycle

1. **Draft** — generate unified diff (gold case: `redact=False` → `redact=True`).
2. **Human review** — approve or reject the proposal.
3. **Sandbox apply** — write diff into a temporary workspace under `backend/data/remediation_sandbox/`; never push; never modify production trees outside allowlist.
4. **Rollback** — restore sandbox from pre-apply snapshot if needed.
5. **Retest** — allowlisted regression tests (e.g. `test_request_logger_regression.py`).

## Safety invariants

| Invariant | Status in gold proof |
|---|---|
| Real unified diff applied | Yes (sandbox only) |
| Production modification | 0 |
| Autonomous closure | 0 |
| Raw-value leakage | 0 |

## What it is not

- Not a CI/CD merge bot.
- Not a remote git push.
- Not autonomous incident closure.
- Not available when source location is unknown (diagnosis must say “Not established”).
