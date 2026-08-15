# False-Positive Suppression Model

**Modules:** `app/services/sensitive_value_validation_service.py` (produces
negative signals) + `app/services/sensitive_exposure_policy_service.py`
(hard-suppresses on them, via `app/rules/exposure_policy_rules.yaml`'s
`hard_suppress_signals` list)
**Consumed by:** `sensitive_exposure_engine.analyse()` — see
`docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md`.

## Two-stage suppression

A regex/field-alias candidate detection is deliberately over-inclusive — it
is cheap to say "this looks like it could be a phone number" and expensive to
say "this definitely is one." False-positive suppression happens in two
separable stages:

1. **Validation** (`sensitive_value_validation_service.validate_candidate`)
   inspects the actual value (format, checksum, entropy, field-name context)
   and returns positive/negative signals plus a 0–1 `validation_score`. This
   stage never drops a candidate outright — it always returns a
   `ValidationResult`, even for a very-low-confidence one.
2. **Policy hard-suppression**
   (`sensitive_exposure_policy_service.evaluate`) checks whether any of the
   validator's `negative_signals` intersects the YAML-configured
   `hard_suppress_signals` set. If so, the decision is
   `suppressed_false_positive` **immediately**, before any exposure-location
   reasoning even runs — a suppressed candidate is never accidentally
   promoted to `unsafe_exposure` just because it happens to sit in a log
   channel.

A suppressed finding is not silently discarded from the engine's output: by
default `sensitive_exposure_engine.analyse(include_suppressed=False)` drops
it from the returned list, but the caller can request
`include_suppressed=True` to see suppressed candidates too (e.g. for
debugging or audit purposes) — the finding still carries
`safety_status="suppressed"` and its suppression reason.

## The hard-suppress signal catalogue

From `exposure_policy_rules.yaml`'s `hard_suppress_signals`, each one raised
by a specific validator in `sensitive_value_validation_service.py`:

| Signal | Raised by | Why it means "not this type" |
|---|---|---|
| `timestamp_like_number` | `_validate_phone` | A 10–13 digit number matching `^1[5-9]\d{8,12}$` (Unix-epoch-millisecond shape) in a field whose name doesn't say "phone"/"mobile" is far more likely a timestamp than a Nepal phone number. |
| `phone_format_mismatch` | `_validate_phone` | Fails both the Nepal-prefix pattern (`9[78]\d{8}`) and the generic 10–13 digit plausibility check. |
| `unrelated_field_name` | `_validate_phone` | The field name is a known non-phone identifier (`build_number`, `request_id`, `sequence`, `counter`). |
| `digit_range_failed` | `_validate_card` | Not all-digit or outside the 13–19 digit range real card numbers occupy. |
| `luhn_failed` | `_validate_card` | Passes the digit-range check but fails the Luhn checksum — a strong, well-established signal that a digit string is not a real issued card number (`NEG-LUHN-FAIL-CARD` in the evaluation dataset exists specifically to prove this). |
| `jwt_structure_failed` | `_validate_jwt` | Does not match the three-base64url-segment JWT shape (`eyJ...\....\....`). |
| `email_structure_failed` | `_validate_email` | Does not match a minimal `local@domain.tld` shape. |
| `digit_shape_failed` | `_validate_otp_pin` | Not a 4–8 digit string. |
| `missing_auth_field_context` | `_validate_otp_pin` | A 4–8 digit string *is* shaped like an OTP/PIN, but the field name carries none of `otp`/`pin`/`passcode`/`auth` — a bare digit string in an arbitrary field (e.g. `verification_code` alone, per `NEG-OTP-NO-AUTH-CONTEXT`) is not enough on its own. |
| `pem_marker_missing` | `_validate_private_key` | Missing the `BEGIN ... PRIVATE KEY` PEM marker. |
| `below_minimum_length` | `_validate_api_key` | Shorter than 12 characters. |
| `low_entropy_credential_candidate` | `_validate_api_key` | No recognised vendor prefix (`pk_`/`pk-`/`sk_`/`sk-`/`AKIA`/`ghp_`/`glpat-`) **and** Shannon entropy below `2.5` bits/char — a low-entropy string with no structural credential marker is more likely a repetitive placeholder than a real key. |
| `missing_field_context` | `_validate_api_key` | Entropy/prefix checks pass, but neither the value nor the field name (`key`/`secret`/`token`) supports an API-key interpretation. |
| `financial_ref_too_short` | `_validate_financial_ref` | Shorter than 6 characters and matches neither a wallet nor transaction-reference format/field hint. |
| `empty_value` | `validate_candidate` (top-level) | The stripped value is empty. |

A separate, non-hard-suppress signal — `already_masked_pattern` (from the
`_MASKED_RE` check at the top of `validate_candidate`, matching `**`-runs,
`[masked]`, or `x`-runs) — routes to `already_safely_masked` rather than
`suppressed_false_positive`, since an already-masked value is a real
(mitigated) finding, not a false positive; see
`docs/EXPOSURE_POLICY_MODEL.md`.

## Why suppression lives in two places instead of one

Keeping "does this value look valid" (validator) separate from "should this
be suppressed as a false positive" (policy's `hard_suppress_signals` list)
means:

- The validator's signals are reusable for **confidence scoring** too (they
  feed `sensitive_detection_confidence_service`'s negative-signal penalty
  even for candidates that aren't hard-suppressed), not just for a binary
  keep/drop decision.
- Which signals are severe enough to hard-suppress is a **policy** choice,
  configurable in YAML without touching validator code — e.g. if a future
  reviewer decides `missing_field_context` for API keys is too aggressive
  and should only lower confidence rather than suppress outright, that is a
  one-line YAML change (removing it from `hard_suppress_signals`), not a
  validator rewrite.

## Known limitations

- The hard-suppress list is a fixed set curated by inspection of the
  validators' signal vocabulary, not derived from measured false-positive
  rates on real traffic.
- Suppression is all-or-nothing per signal: there is no "suppress with 50%
  confidence penalty instead of full suppression" tier between the
  confidence model's negative-signal penalty (max `-0.30`) and a hard
  `suppressed_false_positive` verdict.
- A validator that raises a negative signal *not* in `hard_suppress_signals`
  (e.g. `non_nepal_prefix`, `weak_password_context`, `weak_format`) only
  reduces confidence — it never suppresses. This is intentional (these
  signals indicate lower certainty, not "definitely wrong"), but it means the
  suppression/non-suppression boundary is drawn by which specific string a
  validator happens to append to `negative_signals`, so a new validator must
  deliberately choose the right list to land in.
- `_validate_financial_ref`'s `weak_format` fallback (identifier length ≥ 6
  with no wallet/transaction format or field-name support) still returns
  `valid=True` with a low `0.55` score rather than a negative signal at all
  — a case that arguably deserves suppression currently only gets a
  confidence penalty instead. See `docs/LIMITATIONS_AND_FUTURE_WORK.md`.
