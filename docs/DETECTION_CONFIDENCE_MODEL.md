# Detection Confidence Model

**Module:** `app/services/sensitive_detection_confidence_service.py`
(`ENGINE_VERSION = "confidence_engine_v1"`)
**Consumed by:** `sensitive_exposure_engine.analyse()` — see
`docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md` for the full pipeline.

## What this replaces

Before the unified exposure engine, "confidence" for a sensitive-data finding
meant three different, inconsistent things depending on which code path
produced it: a hardcoded `confidence=0.92` constant on the Live-Monitor-alert
→ `Detection` link, a raw unbounded float directly off a detector
(`Detection.confidence`), and a string label
(`SensitiveDataClassification.confidence_label`) with no defined mapping back
to a number. None of these were explainable — a `0.92` could not be
decomposed into "why 0.92 and not 0.7?"

`score_confidence()` is the one confidence scorer in the engine: a
deterministic weighted sum with a full per-contribution breakdown, always a
function of its inputs (same inputs → same output, no hidden state, no
per-type hardcoded shortcut).

## The six weighted components

| Component | Weight | Source |
|---|---|---|
| `pattern_strength` | 0.30 | Regex/rule confidence from candidate detection, or a neutral `0.5` when the candidate came only from a structured field-name alias (a name match alone is weaker evidence than a matched pattern). |
| `validator_score` | 0.30 | `ValidationResult.validation_score` from `sensitive_value_validation_service` (e.g. `0.92` for a Luhn-valid card, `0.15` for a below-minimum-length API-key candidate). |
| `field_relevance` | 0.15 | `1.0` if the field/JSON-path name supports the claimed type, `0.5` neutral, `0.0` if it contradicts it. |
| `exposure_location` | 0.10 | How much the observed channel corroborates an actionable finding — see the location-support table below. |
| `policy_modifier` | 0.10 | Whether the exposure-policy decision corroborates or undercuts the finding (an `unsafe_exposure` decision scores `1.0`; `suppressed_false_positive` scores `0.0`). |
| `entropy` | 0.05 | Normalised Shannon entropy of the raw value (only meaningful for credential-like free-form values; structured low-entropy identifiers like phone numbers still get a small, non-dominant contribution here). |

Each component is clamped to `[0, 1]`, multiplied by its weight, and rounded
to 6 decimal places in the returned `breakdown` dict so the exact arithmetic
is auditable. The six weighted contributions are summed, then a **flat
per-negative-signal penalty** (`0.05` per distinct negative signal, capped at
`0.30` total) is subtracted, and the final score is clamped to `[0, 1]` and
rounded to 4 decimal places.

```
score = clamp(sum(weighted_components) - min(0.30, 0.05 * len(negative_signals)), 0, 1)
```

### Exposure-location support table

```
application_log / request_header_log / error_message /
third_party_log / file_export / webhook_payload /
ai_prompt_context                                        -> 1.0
query_string                                              -> 0.9
cache_entry / response_body                               -> 0.8
request_body / database_field                             -> 0.6
request_header_processing                                 -> 0.5
unknown (or anything not listed)                          -> 0.3
```

Durable, externally-visible channels support high confidence; ambiguous or
purely in-process channels support less, independent of the exposure-policy
verdict for that same location (the two concepts are related but not
identical — see `docs/EXPOSURE_POLICY_MODEL.md`).

### Policy-modifier table

```
unsafe_exposure          -> 1.0
uncertain                 -> 0.4
legitimate_processing     -> 0.55
already_safely_masked     -> 0.3
suppressed_false_positive -> 0.0
(anything else)           -> 0.4
```

## Confidence levels

```
score >= 0.85 -> "very_high"
score >= 0.65 -> "high"
score >= 0.40 -> "medium"
else          -> "low"
```

## What the output carries

`ConfidenceResult.to_dict()` returns `confidence_score`, `confidence_level`,
`confidence_breakdown` (the six weighted values plus the negative-signal
penalty, individually), `confidence_positive_signals`,
`confidence_negative_signals`, and `confidence_engine_version` — every one of
these is placed directly on the finding dict, so a reviewer or downstream
report never has to re-derive "why was this scored 0.71."

## Known limitations

- The six weights (0.30/0.30/0.15/0.10/0.10/0.05) and every table value
  above are **fixed constants tuned by inspection**, not fit to any labelled
  dataset or calibrated against a real error rate. Per `AGENT.md`, this score
  must never be described as a calibrated probability — it is an explainable
  relative ranking, not "the probability this finding is a real exposure."
- Entropy is computed over the raw value's characters with a fixed
  `_MAX_ENTROPY_BITS_PER_CHAR = 4.5` normalisation constant; this
  meaningfully separates a high-entropy API key from a low-entropy repeated
  string, but is a weak signal for naturally low-entropy identifiers (phone
  numbers, national ID numbers) — those rely on `validator_score` and
  `pattern_strength` instead, and entropy's 0.05 weight is deliberately small
  so it cannot dominate the score for such types.
- `field_relevance` is supplied by the caller (`sensitive_candidate_detection_
  service`), not computed inside this module; this module trusts whatever
  0/0.5/1.0 value it receives.
- There is no per-taxonomy-type override of the weights — every finding, from
  a private key to a phone number, is scored with the same six weights. A
  type with a fundamentally different risk profile cannot currently get a
  different weighting scheme without a code change.
