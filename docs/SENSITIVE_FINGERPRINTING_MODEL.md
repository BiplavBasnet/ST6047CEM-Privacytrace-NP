# Sensitive-Value Fingerprinting Model

**Module:** `app/services/sensitive_fingerprint_service.py`
(`FINGERPRINT_METHOD = "hmac_sha256_v1"`, `FINGERPRINT_VERSION = "v1"`), built
on `app/services/taxonomy_validator_service.hmac_fingerprint`.
**Consumed by:** `sensitive_exposure_engine.analyse()` — see
`docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md`.

## Why fingerprinting exists at all

PrivacyTrace never stores or displays a raw sensitive value once a finding is
built (raw values live only in the local scope of a single `analyse()` call
and are discarded on return). But an analyst still needs to answer "is this
the same phone number/wallet ID that appeared in that other alert?" without
ever seeing either raw value side-by-side. A fingerprint is a one-way,
stable digest of the value that supports this equality comparison — same
input always produces the same fingerprint — without being reversible.

## The one supported method

`fingerprint(value, taxonomy_type) -> {"fingerprint", "method", "version"}`
wraps `taxonomy_validator_service.hmac_fingerprint`:

```
normalized = normalize_identifier(value).casefold()   # strips whitespace, "-", "/"
message    = f"privacytrace-detection-v1\0{taxonomy_type}\0{normalized}"
digest     = HMAC-SHA256(key=settings.detection_hmac_key, message)
fingerprint = f"HMAC-SHA256-V1:{digest.hexdigest()}"
```

Two properties this construction guarantees:

- **Keyed, not plain.** The HMAC key (`DETECTION_HMAC_KEY`) makes the digest
  infeasible to brute-force even for a low-entropy, highly predictable input
  space (a 10-digit Nepal phone number has at most ~10^9 possible values —
  a plain unkeyed SHA-256 over that space is fully rainbow-table-able; an
  HMAC keyed with a secret is not, as long as the key itself stays secret).
- **Type-scoped.** The taxonomy type is mixed into the HMAC message, so the
  same string value under two different taxonomy types (unlikely in
  practice, but not impossible for a generic numeric string) produces two
  different fingerprints — they are never confusable as "the same
  sensitive value."

`fingerprint()` **raises `FingerprintUnavailableError`** rather than
silently falling back to an unkeyed hash if `DETECTION_HMAC_KEY` is not
configured. There is no degraded-but-working mode; a missing key is a hard
configuration error the caller must fix, not a silent security downgrade.

## The legacy hash this replaces

`detection_service.hash_raw_value` (still present for that older code path,
not yet migrated onto the unified engine — see
`docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md`'s "Known limitations") produces a
**plain, unkeyed** `sha256:<hex>` digest. For a predictable, low-entropy
identifier (phone number, national ID, account number), this is
brute-forceable: an attacker with the digest can enumerate the entire
identifier space and check each candidate's SHA-256 against it.

`sensitive_fingerprint_service` provides two helpers specifically so this
legacy format is never mistaken for the new one:

- `is_legacy_sha256(hash_value)` — `True` if the value starts with the
  `sha256:` prefix.
- `is_hmac_fingerprint(hash_value)` — `True` if it starts with
  `HMAC-SHA256-V1:`.

Any code comparing two fingerprints for equality (deduplication, grouping,
"has this exact value been seen before") must use these guards to refuse
comparing a legacy digest against an HMAC one as if they were equivalent —
they are computed differently and a match/mismatch between the two formats
carries no meaning.

## What fingerprinting does *not* do

- It is **not** used for `docs/LIVE_ALERT_GROUPING.md`'s recurrence
  detection. Alert grouping deliberately keys on non-sensitive dimensions
  (`sensitive_type`, `exposure_location`, `service`, `endpoint`,
  `environment`) precisely so the grouping key never depends on the raw
  value or its fingerprint — see that document for why value-level grouping
  was intentionally avoided.
- It does not support fuzzy/approximate matching — normalisation strips only
  whitespace, hyphens, and slashes, and casefolds; two values that a human
  would consider "the same identifier" but differ by any other formatting
  (e.g. a phone number with a country-code prefix vs. without) produce
  different fingerprints.
- It is skipped entirely when a finding is already masked
  (`already_safely_masked` decision) — there is no reason to fingerprint a
  value the engine itself never held as a distinguishable raw form worth
  tracking.

## Known limitations

- `DETECTION_HMAC_KEY` is a single, non-rotatable key in current
  configuration; there is no key-versioning scheme, so rotating the key
  invalidates the ability to match old fingerprints against new ones (a
  deliberate trade-off — see `docs/KEY_MANAGEMENT_RUNBOOK.md` for the
  broader key-management posture).
- Normalisation (`normalize_identifier` + casefold) is a fixed, generic
  transform; it is not taxonomy-aware beyond that (e.g. it does not know
  that `+977-9841234567` and `9841234567` are the "same" Nepal phone number
  once the country code is stripped — those would fingerprint differently
  today).
- `detection_service.hash_raw_value` remains available but is **deprecated**
  for sensitive identifiers. Detection and live-safety paths now prefer
  `value_fingerprint` / `sensitive_fingerprint_service.fingerprint` and
  leave `raw_value_hash` null when HMAC is unavailable — there is **no
  SHA-256 downgrade**.
