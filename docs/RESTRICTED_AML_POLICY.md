# Restricted AML Policy

Restricted AML and compliance categories are internal-only. The application detects possible exposure of existing restricted fields; it does not calculate customer risk, infer suspicious activity, recommend STR/SAR filing, or provide legal conclusions.

## Disclosure rules

- Ordinary APIs receive one generic `restricted_compliance_information` marker.
- Authorised restricted APIs receive category-level metadata only; masked values and fingerprints are removed.
- **Fail-closed on `EXTERNAL_CHANNELS`:** `customer_notification`, `external_ai`, `external_webhook`, `general_report`, and `search_index` never receive restricted AML records (`disclosure_decision` returns `allowed=False`).
- Audit records contain generic category codes, policy decisions, references, and reason codes only.

Restricted access uses the existing `restricted_detection:read` permission. General taxonomy, alert, timeline, report, or auditor access does not grant restricted AML access by itself.

## AI payload capture seam

AI remediation builds a masked incident summary, drops detections whose
`sensitive_type` is restricted for `external_ai`, then runs
`sanitize_payload(..., channel="external_ai")` before the safety gateway and
provider call. Restricted material is removed (not redacted into the payload)
on external channels. The assistant remains advisory and disabled by default.

The policy service is defense in depth. Every outbound notification, AI, report, export, and webhook integration must also invoke the restricted-data filter at its own trust boundary before production enablement.

