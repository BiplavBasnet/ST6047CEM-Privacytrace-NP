# Data Retention Policy

Operational prototype defaults:
- Raw sensitive values are never persisted after detection/masking.
- Fingerprints are keyed HMAC digests (not reversible without the key).
- Governed lifecycle and verification history uses restrictive references and cannot be cascade-deleted with an incident. Other prototype evidence domains retain their documented schema-specific deletion behavior.
- Audit logs and integrity ledger entries are append-oriented; no automatic purge in this Bachelor prototype.

No automatic scheduler or demonstrated purge runtime exists. Operators must run an explicitly reviewed retention process; production deployments need their own retention windows, legal holds, backups, and purge jobs.
