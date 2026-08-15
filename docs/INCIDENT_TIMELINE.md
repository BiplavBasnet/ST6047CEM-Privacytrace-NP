# Incident Timeline

The incident timeline is a read-only projection over existing incident, evidence, detection, alert, assessment, decision, review, remediation, containment, preventive-control, verification, notification, audit, and integrity records. It does not duplicate those records in a new timeline table.

## API

`GET /incidents/{incident_id}/timeline` supports optional `event_type`, `lifecycle_stage`, and `limit` filters.

Events are ordered by observed time, recorded time, and stable event identifier. Delayed ingestion is labelled when recording occurs more than five minutes after the observed time. Missing original time is labelled `unknown_original_time`.

Timeline summaries expose categories, states, reason codes, evidence references, and pseudonymous identifiers only. Raw payloads, file contents, customer identifiers, credential values, notification destinations, and message bodies are excluded.

Records created before the integrity ledger was enabled remain explicitly labelled `not_yet_verified`. This is a traceability aid, not proof that an event or root cause is correct.

