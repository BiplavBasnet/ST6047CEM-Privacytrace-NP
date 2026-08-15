# Governance API

All endpoints require the existing JWT and permission dependencies. Mutation requests reject unknown fields and return safe errors without echoing request values.

## Main endpoint groups

- `/incidents/{incident_id}/breach-decisions` and `/breach-decisions/{decision_id}/*`
- `/incidents/{incident_id}/provenance` and `/evidence/{evidence_id}/provenance/*`
- `/integrity/*` and `/incidents/{incident_id}/integrity/*`
- `/incidents/{incident_id}/counterfactual-analysis`
- `/breach-alerts`, `/alerts/metrics`, `/alerts/overdue`, and `/alerts/{alert_id}/*`
- `/incidents/{incident_id}/timeline`
- `/incidents/{incident_id}/preventive-controls` and `/preventive-controls/{control_id}/*`
- `/sensitive-data-taxonomy/*`
- `/incidents/{incident_id}/exposure-profiles` and `/exposure-profiles/{profile_id}/*`
- `/incidents/{incident_id}/restricted-detections`

The API exposes masked values, category codes, pseudonymous subject references, evidence references, and review state. It does not expose raw credentials, customer identifiers, destinations, message bodies in delivery logs, or restricted AML content to ordinary roles.
