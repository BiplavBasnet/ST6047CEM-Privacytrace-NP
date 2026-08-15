# Contextual Detection

Contextual detection classifies structured field labels using the versioned taxonomy. It combines aliases, negative context, source context, format validation, masking, and optional HMAC-SHA256 fingerprints.

The detector returns `possible`, `probable`, `validated`, `rejected`, or `requires_human_review`. These labels describe classification confidence only. They are separate from root-cause confidence, breach severity, privacy harm, and alert severity.

## Safety

- Raw values are never returned or audited.
- Predictable identifiers use keyed HMAC-SHA256, not plain hashes.
- Passwords, tokens, CVVs, transaction amounts, documents, and AML content use category-only masking where configured.
- Restricted AML classifications remain internal-only and customer-notification prohibited.
- Synthetic preview requires `synthetic: true`, is disabled by default, and never persists input.

`POST /taxonomy/contextual-preview` is intended only for explicitly enabled synthetic development checks. Persisted classifications are available through `GET /incidents/{incident_id}/sensitive-classifications` with role filtering. Dedicated restricted readers may use `GET /incidents/{incident_id}/restricted-detections`; other roles cannot use that route.

Document metadata classification does not imply OCR, document authenticity validation, or proof that the detected value is genuine or active.


