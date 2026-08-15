# Nepal Financial Data Taxonomy

The versioned `np-dfs-1.0.0` taxonomy covers eight areas:

1. Identity identifiers.
2. KYC documents and biometric metadata.
3. Financial accounts and wallets.
4. Payment-card data.
5. Authentication credentials.
6. Transaction information.
7. Restricted AML/compliance information.
8. Merchant KYC and credentials.

Each category defines field aliases, context and negative-context terms, validators, masking and HMAC fingerprint strategy, default severity, possible harms, containment recommendations, notification policy, restrictions, and known limitations.

## API

- `GET /taxonomy/categories` and exact route `GET /sensitive-data-taxonomy`
- `GET /taxonomy/version` and exact route `GET /sensitive-data-taxonomy/version`
- `POST /taxonomy/validate` and exact route `POST /sensitive-data-taxonomy/validate`
- `GET /sensitive-data-taxonomy/{taxonomy_code}`
- `GET /taxonomy/restricted-policy`

Restricted AML categories are omitted from ordinary taxonomy responses. The taxonomy supports classification and review; it does not make legal, regulatory, AML, fraud, or breach determinations.

## Shared ingestion pipeline

Classification runs through `privacy_ingestion_pipeline_service`, shared by
detection, live monitor, scanner bridge, and SIEM import. Callers persist with
`commit=False` and refresh exposure profiles after writes.

Detection classifies on the **pre-mask raw span value** (never persisted raw)
with `allow_fingerprint=True` so taxonomy matching, HMAC fingerprinting, and
AML heuristics see the real value rather than a masked placeholder. Paths that
only hold already-masked fields must pass `allow_fingerprint=False` so
fingerprints are not computed from placeholders.

## Current limitation

The supplied native-script alias strings were irreversibly corrupted and made the YAML invalid. Their lists are disabled in this version. English and romanised Nepali aliases remain active. Native-script aliases must be restored only from a reviewed UTF-8 source with regression fixtures. Nepali-language coverage is therefore incomplete until those aliases are restored and tested.


