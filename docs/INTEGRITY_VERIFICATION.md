# Integrity Verification

## Design

PrivacyTrace-NP uses a deterministic SHA-256 hash chain. It does not use a
blockchain. Each ledger record hashes its protected content, sequence number,
previous hash, creation time, record identity, and schema version.

Canonical JSON sorts object keys, normalises timestamps to UTC, rejects
non-finite numbers, and excludes raw protected content from verification
responses.

## Transactional Ledger Head

The additive migration must create `integrity_ledger_head` with exactly these
fields:

| Field | Database type | Rules |
| --- | --- | --- |
| `id` | `INTEGER` | Primary key, fixed to `1` by check constraint |
| `last_sequence_number` | `INTEGER` | Not null, default `0` |
| `last_record_hash` | `VARCHAR(128)` | Nullable for the empty chain |
| `updated_at` | `TIMESTAMPTZ` | Not null, server default current time |

The migration must insert one row. If ledger records already exist, seed the
head from the highest sequence record; otherwise seed sequence `0` and a
null hash.

Append processing locks row `id = 1` with `SELECT ... FOR UPDATE`, assigns
the next sequence from the head, inserts the record, and updates the head in
the same transaction. A PostgreSQL transaction advisory lock remains around
head creation to prevent a first-write race.

The additive migration must also prevent update or delete of ledger records
and prevent deleting the singleton head. Direct head updates should be limited
to the application database role used by the ledger service.

## Verification

Verification always walks the **global** chain (every ledger record in
sequence), regardless of the requested scope. Runs record
`verification_mode=global_with_scope_membership` and report how many of those
records are members of the requested scope. Incident APIs therefore do **not**
claim an incident-only subchain was verified.

Verification detects:

- Protected-content changes.
- Missing sequence numbers.
- Invalid previous-hash links.
- Rewritten sequence or hash fields.
- Deletion of the final ledger row by comparing records with the locked head.
- A missing head when ledger rows exist.

Failure creates a deduplicated high-severity internal integrity alert.
Verification never repairs or deletes data and never returns protected record
content. Global runs stamp every record; incident-scoped runs stamp only
scope-member records so out-of-scope statuses are not overwritten.

`assert_export_allowed` re-verifies and raises `IntegrityExportBlockedError` on
failure. Report, provenance, and related export routes use this gate.

## API

- `POST /integrity/verify`
- `POST /incidents/{incident_id}/integrity/verify`
- `GET /incidents/{incident_id}/integrity`
- `GET /evidence/{evidence_id}/integrity`
- `GET /breach-decisions/{decision_id}/integrity`
- `GET /integrity/verification-runs/{run_id}`

## Migrations (stabilisation)

- `018_stabilisation_hardening` — integrity failure fingerprints / alerts,
  verification-run scope fields, breach-alert operational hardening, exposure
  profile uniqueness helpers.
- `019_root_cause_evidence_roles` — root-cause evidence-role ID columns.
- `020_integrity_verification_mode` — `verification_mode` on
  `integrity_verification_runs` (default `global_with_scope_membership`).

## Limitations

The chain is global even when verification is requested for an incident. This
preserves cross-record link verification. Scope fields control membership
counts, status views, and audit context, not independent subchains.
