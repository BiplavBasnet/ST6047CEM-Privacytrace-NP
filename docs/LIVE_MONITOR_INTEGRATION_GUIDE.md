# Live Monitor Integration Guide

## How gateway events become alerts

The Integration Gateway converts a supported request into a LiveMonitorEvent.
The safety scanner examines the message, metadata, and structured payload.
Sensitive matches are replaced with masked representations before any API or UI
response is built.

A safe event without a sensitive match creates a normalized evidence record but
no alert. A possible exposure creates a privacy alert with:

- Integration Gateway provenance
- source and service metadata
- masked values only
- raw event hash
- evidence identifier
- missing metadata
- correlation recommendations
- human review required

## How alerts become incidents

An authorised analyst opens the alert and chooses Create incident or Link
incident. The gateway does not confirm an incident automatically. The incident
trace combines the alert with historical evidence, CI/CD evidence,
ScannerBridge-NP findings, access evidence, and retest evidence.

## Metadata and likely-cause analysis

service_name and endpoint connect symptoms to the affected component.
event_time strengthens timeline ordering. deployment_version connects the event
to CI/CD evidence. trace_id and hashed transaction references strengthen
cross-source correlation.

When these fields are absent, PrivacyTrace-NP labels evidence strength as
limited and recommends the missing metadata. A ranked likely cause remains an
assessment supported by available evidence, not established blame.

## Evidence Import relationship

Integration Gateway and Live Privacy Monitor are the primary live-event path.
Evidence Import remains available for:

- historical evidence
- supporting files
- retest evidence
- offline evaluation
- datasets that cannot be forwarded live

## Verification workflow

1. Receive and mask the live event.
2. Review the privacy alert.
3. Create or link an incident.
4. Add technical supporting evidence.
5. Review ranked likely causes and limitations.
6. Record the human decision.
7. Apply remediation outside PrivacyTrace-NP.
8. upload or ingest retest evidence.
9. Run fix verification.
10. Generate the final report.

## Safety and limitations

Do not send real customer data without approval and safeguards. Tokens belong in
a secret manager or protected environment configuration. PrivacyTrace-NP uses
passive event ingestion and complements existing operational monitoring. Vendor
adapters and network configuration remain environment-specific.
