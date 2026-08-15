# Exposure Profiles

Exposure profiles combine reviewed contextual classifications using `np-exposure-1.0.0`. Supported profiles include identity exposure, full KYC dossier exposure, account takeover risk, financial fraud risk, targeted phishing risk, payment-card compromise, merchant compromise, and restricted AML confidentiality exposure.

## Subject-safe grouping

Classifications are combined only when they share a pseudonymous subject reference or, with lower confidence, the same normalized event, evidence record, or detection. The service does not combine unrelated incident-wide values merely because they occurred in one incident.

Each profile records matched rule IDs, taxonomy/ruleset versions, supporting detection and evidence references, possible harms, containment recommendations, missing information, limitations, grouping method, and grouping confidence.

## API

- `GET /incidents/{incident_id}/exposure-profiles`
- `POST /incidents/{incident_id}/exposure-profiles/recalculate`
- `GET /exposure-profiles/{profile_id}`
- `POST /exposure-profiles/{profile_id}/review`
- `POST /exposure-profiles/{profile_id}/reject`
- `GET /exposure-combination-rules` and alias `GET /taxonomy/exposure-combination-rules`

Profiles require human review. They indicate possible combined exposure and do not prove misuse, fraud, account takeover, or legal breach status.


