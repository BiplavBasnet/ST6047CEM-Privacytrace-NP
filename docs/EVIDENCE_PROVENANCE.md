# Evidence Provenance

## Purpose

Evidence provenance records where evidence originated, when it was collected,
which parser and service processed it, and how it relates to decisions and
other evidence. Provenance metadata never contains raw evidence content.

## Records and Relationships

`EvidenceProvenance` stores safe source references, timestamps, component
versions, trace references, SHA-256 content hashes, and an optional parent
evidence ID.

`ProvenanceRelationship` stores typed, explained edges. Every edge requires a
reason. Derivation edges are checked using both entity type and entity ID so
equal IDs in different domains do not create false cycles.

## System write path

Producers use one function: `record_system_provenance`. Defaults:

- `commit=False` — the caller owns the transaction and must commit or roll back.
- `append_integrity=False` — integrity ledger append is opt-in via
  `append_integrity=True`, or a separate explicit
  `append_evidence_integrity_record` call after a successful provenance write.

Ingestion, scanner bridge, and similar services pass `commit=False` and usually
`append_integrity=True`, then commit themselves.

## Validation

Validation reports `complete`, `partial`, `invalid`, or `unverified`.
Checks include:

- Missing source or parser metadata.
- Invalid or circular parent relationships.
- Source, collection, and ingestion timestamp order.
- Invalid or mismatched SHA-256 content hashes.
- Decision references to unavailable incident evidence.
- Incident evidence with no provenance record.

Cycle detection for parent links is **node-local** (`node_has_cycle` from the
evidence under review), not a full-graph DFS over unrelated nodes. Relationship
creation still rejects candidate edges that would close a cycle.

Path traversal is breadth-first, bounded to 12 edges and 100 returned paths,
and never revisits an entity within one path.

Provenance and report export routes call integrity `assert_export_allowed`; a
failed global chain blocks the export.

## API

- `GET /incidents/{incident_id}/provenance`
- `GET /evidence/{evidence_id}/provenance`
- `POST /evidence/{evidence_id}/provenance/validate`
- `GET /incidents/{incident_id}/provenance/validation`
- `GET /breach-decisions/{decision_id}/provenance-path`
- `GET /root-causes/{root_cause_id}/provenance-path`
- `GET /incidents/{incident_id}/provenance/export`

The export contains safe metadata only. It excludes raw evidence and sensitive
values.

## Limitations

Provenance quality depends on ingestion producers supplying source and version
metadata. Historical evidence without those fields remains partial or
unverified; the service does not invent missing provenance.
