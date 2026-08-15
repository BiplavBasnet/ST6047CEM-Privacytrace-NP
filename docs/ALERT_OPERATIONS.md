# Breach Alert Operations

`BreachAlert` is the operational customer-exposure alert. It is separate from the live detector `PrivacyAlert` and does not turn a pattern match into a verified breach.

## Additive state

The operational extension records occurrence and duplicate counts, evidence links, assignment, acknowledgement and containment deadlines, suppression, escalation, and reopening. Existing alert fields and states remain unchanged.

## API

- `GET /breach-alerts`
- `GET /breach-alerts/metrics` and exact alias `GET /alerts/metrics`
- `GET /breach-alerts/overdue` and exact alias `GET /alerts/overdue`
- `POST /breach-alerts/{alert_id}/assign` and `POST /alerts/{alert_id}/assign`
- `POST /breach-alerts/{alert_id}/suppress` and `POST /alerts/{alert_id}/suppress`
- `POST /breach-alerts/{alert_id}/unsuppress` and `POST /alerts/{alert_id}/unsuppress`
- `POST /breach-alerts/{alert_id}/escalate` and `POST /alerts/{alert_id}/escalate`
- `POST /breach-alerts/{alert_id}/reopen` and `POST /alerts/{alert_id}/reopen`
- `POST /breach-alerts/{alert_id}/evidence/{evidence_id}`

Critical credential alerts require time-bounded suppression. Permanent critical-alert suppression requires an administrator override. Reopening is allowed only from a terminal state and preserves the reopen count and reason.

## Escalation context flags

Recommended escalation evaluates YAML rules against alert severity and
deadlines. Context flags are match conditions, not automatic skips:

- `failed_containment`
- `failed_notification_delivery`
- `integrity_failure`

A rule that requires one of these flags matches only when that condition is
true for the alert’s incident. Rules that omit a flag are unaffected. Manual
`POST .../escalate` remains an explicit reviewed action when escalation is
enabled by policy.

## Metrics

Metrics use statuses, timestamps, counts, and identifiers only. They include active, overdue, suppressed, escalated, reopened, false-positive, duplicate-prevention, failed-containment, and failed-delivery counts plus median acknowledgement and containment times. They never include alert summaries, customer values, destinations, credentials, or message bodies.

Denominators are explicit:

- `unresolved_alert_count` — alerts not in a terminal status.
- `acknowledged_sample_size` / `contained_sample_size` — how many alerts
  contributed to each median. A null median with sample size `0` means no
  elapsed samples, not zero seconds.

There is no scheduler in this repository. Overdue evaluation runs when the overdue or metrics operations are requested, and escalation remains an explicit reviewed action.


