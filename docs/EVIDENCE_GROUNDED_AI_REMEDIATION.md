# Evidence-Grounded AI Remediation

PrivacyTrace-NP produces **one primary, best-supported remediation** for a specific sensitive-data exposure and ranked likely root cause.

## Governance model (mandatory)

AI proposes → Human authorises → Controlled tooling applies in a controlled test workspace → Allowlisted tests evaluate → PrivacyTrace verifies using retest evidence → Human confirms outcome.

Never: AI diagnoses → AI modifies production → AI declares success.

## Distinctions

| Layer | Meaning |
| --- | --- |
| Evidence-backed fact | Masked finding, exposure location, timestamps present in store |
| Likely cause | Ranked root-cause candidate after human root-cause review |
| AI diagnosis | Problem statement + technical mechanism (not proven) |
| Human-approved remediation | Accepted / accepted_with_edits diagnosis |
| Proposed patch | Sandbox draft only |
| Tested implementation | Allowlisted profile results |
| Verified outcome | Controlled retest + FixVerification wording |

## Primary API

- `POST /ai-remediation/incidents/{id}/diagnose`
- `POST /ai-remediation/diagnoses/{id}/review`
- `POST /ai-remediation/patches/draft` (accepted only)
- `POST /ai-remediation/sandbox-tests/run` (allowlisted profiles)

## Non-goals

No chatbot, no invented file/function/line, no production git push, no autonomous incident closure.
