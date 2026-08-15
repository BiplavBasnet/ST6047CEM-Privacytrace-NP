# Preventive Controls

Preventive controls turn a reviewed likely cause into a proposed configuration rule, Semgrep rule, regression test, CI check, runtime monitor, manual control, or documentation change. Deterministic templates are the default.

## Lifecycle

`proposed -> reviewed -> approved -> implemented -> verified`

A review may instead request changes. Verification may fail, and an active control may be retired with a reason. The proposer cannot review the same control, the creator or reviewer cannot approve it, and the implementer cannot verify it.

## API

- `GET /incidents/{incident_id}/preventive-controls`
- `POST /incidents/{incident_id}/preventive-controls/generate`
- `POST /preventive-controls/{control_id}/review`
- `POST /preventive-controls/{control_id}/approve`
- `POST /preventive-controls/{control_id}/implement` and exact alias `POST /preventive-controls/{control_id}/mark-implemented`
- `POST /preventive-controls/{control_id}/verify`
- `POST /preventive-controls/{control_id}/retire`

AI generation is disabled by default and is rejected unless a separately approved masked provider is configured. Generated controls are proposals only. They are never deployed or executed automatically. OPA and Semgrep content is stored for review; this slice does not invoke those tools.


