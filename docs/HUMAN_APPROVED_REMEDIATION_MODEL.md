# Human-Approved Remediation Model

## Editable fields (Edit and Accept)

- problem statement
- remediation title
- recommended change
- affected component
- implementation steps
- required tests
- retest requirements
- risks
- rollback plan
- implementation notes

## Provenance (required)

| Field | Meaning |
|---|---|
| `original_ai_payload` | Frozen AI/playbook diagnosis at generation time |
| `approved_payload` | Human-approved (possibly edited) version |
| `edited_fields` | Audit-safe list/diff of changed keys |
| reviewer / decision / decision_reason / approved_at | Review metadata |

AI output is **never overwritten** in place. Reject and request-more-evidence cannot progress to patch.

## UI

`ProblemSpecificRemediationPanel` exposes multi-field edit before accept.
