# Verified Outcome Persistence

Verified remediation learning is **PostgreSQL-backed**. Process memory is not authoritative.

## Tables (migration `024_verified_remediation_completion`)

| Entity | Purpose |
|---|---|
| `verified_remediation_cases` | Durable verified outcomes eligible for ranking |
| `remediation_playbooks` | Pattern templates + success/failure/inconclusive counters |
| `patch_proposals` | Controlled patch metadata + approval/apply/rollback state |

## Survives

- FastAPI restart
- Worker / process restart
- Browser refresh

Proof: `test_gold_lifecycle_patch_apply_test_verify_persist` asserts case + playbook counters after verify; durability checks reopen a DB session.

## Eligibility

Only human-approved remediations with passed (or explicitly recorded) verification and `eligible_for_learning` may increment success counters. Rejected / unverified / inconclusive do not boost positive ranking.
