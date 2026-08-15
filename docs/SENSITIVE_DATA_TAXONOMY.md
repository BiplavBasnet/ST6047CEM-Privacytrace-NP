# Sensitive Data Taxonomy (Canonical Bridge)

`backend/app/services/sensitive_data_taxonomy_service.py` provides one canonical
taxonomy-type name per sensitive-value concept, plus a legacy-alias index so the
historically separate detection paths (Evidence/Phase-5 regex, Live Monitor
hardcoded patterns, Nepal-taxonomy contextual detection, SIEM/ScannerBridge
ingestion) resolve to the same type instead of drifting (`wallet_id` vs.
`wallet_identifier`, `authorization_header` vs. `bearer_token`, etc.).

This does **not** replace the Nepal financial-taxonomy registry
(`nepal_financial_data_taxonomy.yaml` / `taxonomy_registry_service.py`), which
remains the source of truth for structured-field classification, masking
strategy, containment recommendations, and internal-only/restricted handling
per category. It is a narrower bridge used by the unified exposure engine to
normalise the *type name* a candidate is tagged with before validation,
policy, and confidence scoring run.

## Canonical types

Each canonical type (`resolve_taxonomy_type`, `canonical_type_name`,
`category_for`, `sensitivity_for`) carries:

- `taxonomy_type` — the one name the rest of the engine uses (e.g. `phone_number`).
- `category` — `PERSONAL`, `FINANCIAL`, `AUTHENTICATION_SECRET`, `KYC`, or `UNKNOWN`.
- `sensitivity` — `CRITICAL`, `HIGH`, `MODERATE`, or `LOW`.
- `legacy_aliases` — historical detector/type names that resolve to this canonical type.

`TAXONOMY_VERSION = "canonical_v1"` is recorded on findings so future taxonomy
revisions are distinguishable.

## Guarantees

- `canonical_type_name(x)` is deterministic and idempotent:
  `canonical_type_name(canonical_type_name(x)) == canonical_type_name(x)`.
- An unrecognised type hint is never silently dropped: it is returned as its
  own lowercase/trimmed string with `category = UNKNOWN`, `sensitivity = MODERATE`,
  rather than raising or defaulting to a specific known category.
- Alias resolution is case-insensitive and whitespace-trimmed.

## Known limitations

- Legacy aliases were captured from the existing codebase at the time of this
  work (`docs/CORE_ENGINE_BASELINE_AUDIT.md`); a detector name introduced
  elsewhere without being added here will fall back to `UNKNOWN` category /
  `MODERATE` sensitivity rather than being misclassified as something else —
  by design, but it means new detectors must register an alias here to get
  correct category/sensitivity treatment.
- This is a Python-level mapping, not a database-backed versioned registry
  like the Nepal taxonomy; there is no admin UI or API to inspect it beyond
  `list_canonical_types()`.
