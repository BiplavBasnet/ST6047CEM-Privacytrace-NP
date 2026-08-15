# Verification Outcome Model

`VerificationOutcome` is the persisted authoritative verification record for an incident remediation chain.

## Persisted fields (high level)

- Provenance links: analysis, review, diagnosis, remediation action, patch, test execution
- Match booleans: same service / endpoint / exposure location / sensitive type / component
- `tests_passed`, `raw_exposure_after_change`
- `verification_result`, limitations, eligibility for learning

## Learning eligibility

Only human-accepted diagnoses with `verification_result=passed` may influence playbook ranking.

Canonical taxonomy fields passed into learning:

- `sensitive_type`
- `exposure_location`
- `root_cause_category`

These come from diagnosis/playbook context — **never** from `problem_statement` free text.
