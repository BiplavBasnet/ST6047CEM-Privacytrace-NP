# Report Readiness Rules

Report readiness is calculated by `backend/app/services/report_readiness_service.py`.

## Endpoint

`GET /incidents/{incident_id}/report-readiness`

## Checks

- Incident summary is ready.
- Root Cause & Traceability exists.
- Human Review is recorded.
- Remediation action is recorded when review is approved.
- Retest evidence exists when remediation is required.
- Fix Verification exists when remediation is required.
- Confidence limitations are available.

## Important Correction

Existing reports do not prove Human Review or Fix Verification happened. Readiness uses workflow facts, not `reports.length`.

When stages remain incomplete, the report is labelled as a draft.
