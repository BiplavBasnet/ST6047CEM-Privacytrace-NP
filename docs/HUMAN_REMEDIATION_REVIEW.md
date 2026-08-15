# Human Remediation Review

Persisted entity: `RemediationDiagnosis` (`remediation_diagnoses`).

## Gate

Requires an **accepted human root-cause review** before diagnosis generation.

## Reviewer must see

Exposure summary, likely cause, exact problem, source evidence, primary remediation, why selected, proposed change (if available), risks, tests, retest, rollback, limitations.

## Actions

- Accept → may create RemediationAction
- Edit and accept
- Reject (reason required) — does **not** unlock implementation
- Request more evidence — does **not** unlock implementation

AI cannot accept, approve, verify, or close.
