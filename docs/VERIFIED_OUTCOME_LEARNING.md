# Verified Outcome Learning

Service: `verified_outcome_learning_service`.

## What it does

Updates playbook ranking counters from eligible verified outcomes. Does **not** retrain an LLM. Does **not** silently rewrite recommendation policy without audit.

## Eligibility

Requires one complete current exact chain, a passed FixVerification and matching passed VerificationOutcome, applicable safe test, controlled retest, and explicit learning eligibility. Rejected, stale, mismatched, draft, failed, or inconclusive cases cannot improve success ranking. Delivery is idempotent; it does not retrain a model.

## Wording

“Recommendation ranking is informed by previously human-approved and verified remediation outcomes.”

Never: “AI learned by itself.”
