# Security and Privacy Safeguards

- New predictable-identifier grouping uses HMAC-SHA256 with `DETECTION_HMAC_KEY`; plain unsalted hashes are not used for new classifications.
- Affected subjects use pseudonymous HMAC references. Customer directory data is resolved only through an adapter.
- Restricted AML classifications are internal-only and are filtered from customer notifications, external AI context, general reports, and ordinary API responses.
- Approved breach decisions are immutable. Supersession creates a new version and preserves history.
- The integrity ledger uses canonical JSON, a transactionally locked singleton head, and an append-only hash chain. Integrity failure creates a high-priority internal alert and never auto-repairs history.
- Containment, notification, and preventive controls use maker-checker separation. Runtime providers remain non-destructive or disabled by default.
- Customer sending, credential auto-containment, preventive-control AI generation, OPA validation, and Semgrep validation are disabled unless explicitly configured.
- Logs and audit records contain identifiers, reason codes, masked summaries, and evidence references only.

These controls support investigation and policy alignment. They are not a legal determination, compliance certification, or calibrated probability claim.
