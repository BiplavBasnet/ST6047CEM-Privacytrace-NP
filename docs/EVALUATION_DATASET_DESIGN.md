# Evaluation Dataset Design (Phase Q)

**Dataset:** `backend/app/evaluation_data/instance_level_cases.yaml`
(`dataset_version: instance_level_v1`)
**Consumer:** `app/services/instance_level_evaluation_service.py`
**Engine under test:** `sensitive_exposure_engine.analyse()` (see
`docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md`)

## Why a new dataset

The pre-existing evaluation path (`evaluation_metric_service.
SCENARIO_GROUND_TRUTH["scenario_1"]`) measures detection quality as a **set
intersection over unique `sensitive_type` values** for one seeded incident
(`INC-SEED-001`). That has two structural weaknesses this dataset is designed
to fix:

1. **No instance counting.** A log line with two phone numbers and a log
   line with one phone number both reduce to the type set `{"phone_number"}`;
   a missed second occurrence, or a duplicated finding, is invisible to a
   type-set metric.
2. **No negative cases.** `scenario_1` only asserts what *should* be found;
   it has no case that specifically must produce *zero* findings or a
   *non-unsafe* classification. A detector that is maximally trigger-happy
   (flags everything) would still score perfectly on recall against a
   positive-only dataset.

`instance_level_cases.yaml` is a small, fully synthetic, hand-labelled
dataset built to close both gaps, plus test the exposure-decision and
masking dimensions the type-set metric never touched at all.

## Case shape

Each case is a dict with:

- `case_id` — unique, human-readable, prefixed `POS-`/`NEG-` for a quick
  positive/negative signal at a glance (documentation only; the evaluator
  does not branch on the prefix or on `label`).
- `label` — `"positive"` or `"negative"`, documentation only. A "negative"
  case is not necessarily "no findings at all" — `NEG-ALREADY-MASKED-
  PASSWORD` and the two `NEG-LEGITIMATE-PROCESSING-*` cases *do* expect a
  real finding, just not an `unsafe_exposure` one. What makes them
  "negative" is that no *fresh unsafe exposure* should be reported.
- `description` — plain-language rationale for a human reading the dataset.
- `source_type` / `text` / `structured` / `environment` — passed straight
  through to `sensitive_exposure_engine.analyse()`, exactly as a real caller
  would.
- `expected_instances` — an **ordered list**, not a set. Each item is
  `{sensitive_type, exposure_decision?}`. A case with two phone-number
  occurrences declares two list entries; the evaluator compares this against
  the engine's actual findings as a **multiset per `sensitive_type`**
  (`collections.Counter`), so `min(expected_count, predicted_count)` becomes
  true positives, any predicted excess becomes false positives, and any
  expected shortfall becomes false negatives. An empty list means "the engine
  must produce zero findings for this input."
- `raw_value` / `raw_values` — included **only** so the evaluator can assert
  the literal raw value is never present in the engine's finding output
  (masking success / raw-leakage check). These fields are never sent
  anywhere outside the evaluation run itself.

## Case catalogue (15 cases)

| case_id | label | Why it's in the dataset |
|---|---|---|
| `POS-PHONE-LOG` | positive | Baseline unsafe exposure: phone number in an application log. |
| `POS-PHONE-LOG-MULTI` | positive | Two phone numbers, one log line — proves instance counting (2 expected instances, not 1 unique type). |
| `POS-WALLET-EXPORT` | positive | Wallet identifier reaching a file export — unsafe exposure via a different channel. |
| `POS-TXN-THIRDPARTY` | positive | Transaction reference reaching a third-party log sink. |
| `POS-JWT-LOG` | positive | Bearer/JWT token logged — authentication-secret category via a log channel. |
| `POS-APIKEY-ERROR` | positive | API key printed to an error/stderr channel. |
| `POS-PRIVATEKEY-CACHE` | positive | PEM private-key marker captured in a cache snapshot. |
| `POS-PHONE-QUERYSTRING` | positive | Sensitive value in a query string — always unsafe regardless of category (proxy/CDN/access-log/browser-history exposure). |
| `NEG-TIMESTAMP-LIKE-PHONE` | negative | A 10-digit number that matches the timestamp-like shape (`_TIMESTAMP_LIKE` regex), not a Nepal mobile prefix. Must produce **zero** instances — the classic phone-vs-timestamp false-positive trap. |
| `NEG-LUHN-FAIL-CARD` | negative | 16-digit number failing the Luhn checksum. Must produce **zero** instances — proves the validator's checksum gate actually suppresses non-card numbers, not just "looks card-shaped." |
| `NEG-OTP-NO-AUTH-CONTEXT` | negative | A 6-digit value in a field with no authentication-field-name support. Must produce **zero** instances — proves a bare digit string in an arbitrary field is not auto-classified as an OTP. |
| `NEG-ALREADY-MASKED-PASSWORD` | negative | Password already stored in masked form (`****1234`). Expects a real finding, classified `already_safely_masked` — proves the engine still surfaces already-masked values for audit visibility instead of silently dropping them, but never as a fresh unsafe exposure. |
| `NEG-LEGITIMATE-PROCESSING-BEARER` | negative | Bearer token seen only during in-flight `Authorization` header processing (not logged). Expects a finding classified `legitimate_processing`, not `unsafe_exposure` — proves the exposure-location distinction actually changes the verdict for the same category/value shape. |
| `NEG-LEGITIMATE-PROCESSING-PASSWORD` | negative | Password value observed only in a persisted database field. Expects `legitimate_processing`. |
| `NEG-NO-SENSITIVE-CONTENT` | negative | Ordinary log line with no sensitive-looking values at all. Must produce **zero** instances — a sanity baseline that the engine does not hallucinate findings from plain text. |

All phone numbers, wallet IDs, transaction references, tokens, and keys in
the dataset are synthetic placeholders invented for this thesis prototype
(the same convention documented in `docs/scenario_ground_truth.md` and
the project's synthetic-data evaluation policy); none are real customer or production
data.

## What this dataset deliberately does not cover

- **Nepali-script text.** Every case is English/romanised, matching the
  taxonomy's currently-enabled alias set (see
  `docs/LIMITATIONS_AND_FUTURE_WORK.md` — native-script aliases are disabled
  pending a fixture-backed restoration).
- **Every taxonomy type.** The dataset spans 8 sensitive types across the
  engine's categories (phone, wallet, transaction reference, JWT/bearer
  token, API key, private key, password) and 4 exposure decisions
  (`unsafe_exposure`, `already_safely_masked`, `legitimate_processing`, and
  implicitly `uncertain`/absent via the empty-instance cases); it is not
  exhaustive over every `sensitive_type` enum member or every
  `exposure_policy_rules.yaml` rule.
- **Adversarial evasion.** No case attempts obfuscated/encoded/split
  sensitive values designed to evade the regex candidate detector; this
  dataset measures nominal-case correctness, not adversarial robustness.
- **Multi-finding interaction effects.** Every case is evaluated
  independently via one `analyse()` call; there is no case exercising how
  multiple findings across many events interact (e.g. via
  `docs/LIVE_ALERT_GROUPING.md`'s recurrence tracking).

## Extending the dataset

Add a new case to the `cases` list in `instance_level_cases.yaml` following
the shape above; no code change is required unless the new case needs a
sensitive type or exposure-policy rule that does not exist yet. Keep new
values synthetic. If a new case is added to cover a taxonomy type or
exposure-location combination not already represented, note it in the table
above so the coverage claim in this document stays accurate.
