# Controlled Workspace Model

PrivacyTrace-NP controlled patch apply uses **Option B**: gold-fixture only.

## Honest scope

- Workspace wording: **controlled local test workspace** (not a secure process/network sandbox).
- Only the allowlisted gold-standard wallet fixture (`fixtures/gold_standard_wallet/request_logger.py`) may be patched.
- No production modification, no remote push, no generalised multi-repo engine.

## Integrity

- Patch generation requires a non-null `remediation_action_id`.
- Apply transitions `approved_for_sandbox` → `applying` → `applied_to_sandbox`.
- Interrupted apply sets `recovery_required=true`.
- `post_apply_workspace_hash` records the workspace file hash after apply.
- Sandbox regression tests may refuse to run if the workspace hash drifted from the patch record.
