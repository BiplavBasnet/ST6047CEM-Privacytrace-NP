# Breach Decision Records

## Purpose

A breach decision record is a versioned explanation of the evidence, method,
policy, severity, potential privacy harm, containment recommendation, and
notification recommendation used during human review. It is not a legal
determination and a detector match cannot create a confirmed breach decision.

## Lifecycle

1. An analyst creates a draft from an existing impact assessment.
2. A reviewer accepts the decision factors or requests changes.
3. An authorised approver approves a reviewed record.
4. Reassessment creates a new draft that supersedes the current approved
   record.
5. Previous versions remain readable and comparable.

Only one record per incident may have
`superseded_by_record_id IS NULL`. A human override requires a reason.
The creator cannot approve the same record.

## Immutability Contract

Application code permits an approved row to change only through controlled
supersession:

- `status`: `approved` to `superseded`.
- `superseded_by_record_id`: `NULL` to the new decision ID.

Every other approved field remains unchanged. The replacement is inserted in
the same transaction and references the old record through
`supersedes_record_id`.

The additive migration must enforce this at database level:

- A `BEFORE UPDATE OR DELETE` trigger rejects changes to approved rows.
- The update exception permits only the two-field transition above.
- A factor trigger rejects update or delete when its parent decision is
  approved or superseded.
- Foreign keys use `RESTRICT` for decision history.
- The partial unique index permits one current decision per incident.

## API

- `POST /incidents/{incident_id}/breach-decisions`
- `GET /incidents/{incident_id}/breach-decisions`
- `GET /breach-decisions/{decision_id}`
- `POST /breach-decisions/{decision_id}/review`
- `POST /breach-decisions/{decision_id}/approve`
- `POST /breach-decisions/{decision_id}/supersede`
- `GET /breach-decisions/{decision_id}/factors`
- `GET /breach-decisions/{decision_id}/differences`

The differences response shows added and removed evidence, changed factors,
changed severity and harm outputs, recommendation changes, uncertainty, and
human overrides.

## Safeguards

Decision inputs use evidence IDs and masked categories. Raw customer data,
credentials, AML investigation data, and complete financial identifiers must
not be stored in decision JSON, audit details, or API errors.

## Limitations

Router registration and the additive database migration are intentionally
outside this domain slice. Until both are integrated, the router module exists
but its endpoints are not exposed by the application.
