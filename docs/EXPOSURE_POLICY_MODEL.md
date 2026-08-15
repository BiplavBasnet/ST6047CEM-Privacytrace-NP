# Exposure Policy Model

**Module:** `app/services/sensitive_exposure_policy_service.py`
**Rules:** `app/rules/exposure_policy_rules.yaml` (`policy_version:
exposure_policy_v1`)
**Consumed by:** `sensitive_exposure_engine.analyse()` — see
`docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md` for the full pipeline this is one
stage of.

This document is a focused reference for the exposure policy stage alone: how
"a sensitive-looking value was observed" becomes one of four explainable
`ExposureDecision` verdicts. For the confidence score that layers on top of
this decision, see `docs/DETECTION_CONFIDENCE_MODEL.md`. For why some
candidates never reach this stage at all, see
`docs/FALSE_POSITIVE_SUPPRESSION.md`.

## The problem

A regex or field-name match only proves a value *looks like* a sensitive
type. It says nothing about whether its presence is dangerous: a phone
number sitting in a validated request body being processed is expected and
safe; the same phone number written into an application log line that a
dozen engineers and a log-aggregation vendor can read is a real exposure.
Without an explicit policy layer, every detector either has to hard-code this
distinction per call site (which is what `live_monitor_safety_service.py`,
`detection_service.py`, and `contextual_detection_service.py` historically
did, each slightly differently) or ignore it entirely and treat every match
as equally alarming.

## Inputs to a policy decision

`evaluate(taxonomy_type, sensitivity, exposure_location, source_type,
field_name, environment, masking_state, negative_signals)`:

- `taxonomy_type` → resolved to a `SensitiveCategory`
  (`AUTHENTICATION_SECRET`, `FINANCIAL`, `KYC`, `PERSONAL`, ...) via
  `sensitive_data_taxonomy_service.category_for()`. Rules match on category,
  not the raw type string, so new taxonomy types automatically inherit their
  category's existing rules.
- `exposure_location` — one of the `ExposureLocation` enum values (see
  `docs/UNIFIED_EXPOSURE_DETECTION_ENGINE.md` §"Exposure location" for how
  this is inferred from `source_type` + context).
- `masking_state` (`"raw"` / `"masked"`) and `negative_signals` (a list of
  strings from `sensitive_value_validation_service.ValidationResult`) — used
  for the two short-circuit checks below.
- `field_name`, `environment` — optional extra dimensions a rule can match
  on (`field_name_contains`, `environments`).

## Decision order (first match wins)

1. **Hard suppression.** If any of `negative_signals` intersects
   `hard_suppress_signals` (from the YAML file — currently 15 signals such as
   `luhn_failed`, `timestamp_like_number`, `missing_auth_field_context`),
   the decision is `suppressed_false_positive` immediately, before any
   location-based rule is even consulted. See
   `docs/FALSE_POSITIVE_SUPPRESSION.md` for the full signal list and
   rationale.
2. **Already masked.** If `masking_state == "masked"` or a negative signal is
   `already_masked_pattern`, the decision is `already_safely_masked`. This
   runs *before* the general rule table so a masked value is never
   miscategorised as a fresh `unsafe_exposure` just because it happens to sit
   in a log channel.
3. **YAML rule table**, evaluated top-to-bottom; the first rule whose
   declared dimensions (`categories`, `sensitivity_levels`,
   `exposure_locations`, `source_types`, `environments`,
   `field_name_contains`) all match wins. A dimension the rule omits matches
   everything (a rule with no `environments` key applies to every
   environment). Current rules, in file order:
   - `sensitive_value_in_query_string` — **any** category in a query string
     is `unsafe_exposure` (query strings are commonly captured by proxies,
     CDNs, web-server access logs, and browser history, regardless of what
     kind of value it is).
   - `authentication_secret_logged` — `AUTHENTICATION_SECRET` in a log-like
     or externally-shared channel (`application_log`, `request_header_log`,
     `error_message`, `third_party_log`, `response_body`, `cache_entry`,
     `file_export`, `webhook_payload`, `ai_prompt_context`) →
     `unsafe_exposure`.
   - `authentication_secret_processing` — the same category, but only seen
     in `request_header_processing` / `request_body` / `database_field` →
     `legitimate_processing`.
   - `financial_or_kyc_identifier_leaked` — `FINANCIAL`/`KYC` categories in
     the same log-like/export/webhook/AI-prompt channel set →
     `unsafe_exposure`.
   - `personal_data_leaked` — `PERSONAL` category in
     `application_log`/`third_party_log`/`ai_prompt_context`/`file_export`/
     `webhook_payload` → `unsafe_exposure`.
   - `processing_context_default` — anything left over in `request_body` /
     `database_field` / `request_header_processing` →
     `legitimate_processing`.
4. **No rule matched → `uncertain`.** The policy never guesses; an
   unmatched combination fails closed to human review rather than being
   silently classified as safe or unsafe.

## Design choices worth calling out

- **Category-based, not type-based, matching.** Rules key off
  `SensitiveCategory`, so e.g. adding a new `KYC`-category taxonomy type
  automatically picks up `financial_or_kyc_identifier_leaked` without a YAML
  change. A rule can still narrow to specific dimensions
  (`field_name_contains`) when a category-level rule is too coarse.
  Currently no rule uses `field_name_contains` or `sensitivity_levels`; they
  exist in the matcher for future rules that need finer-grained
  discrimination than category + location alone.
- **Query strings are always unsafe, unconditionally.** This is the one rule
  that ignores category entirely — the reasoning is about the channel
  (widely logged by infrastructure outside the application's control), not
  the value's sensitivity classification.
- **YAML-configurable, code-stable.** The matching/precedence *logic* lives
  in Python (`_rule_matches`, `evaluate`); the *rules themselves* live in
  YAML so a new location/category combination can be added or re-prioritised
  without a code change or redeploy of the matching engine, at the cost of a
  cache (`@lru_cache` on `_load_cached`, cleared via
  `reset_policy_cache()`) that must be invalidated after an edit in a
  long-running process.
- **Fails closed, never fails open.** There is no "default to safe" branch;
  every code path either returns a specific decision backed by a rule/signal
  or `uncertain`. `uncertain` findings still surface to a human reviewer
  (they are not silently dropped) — see `include_suppressed` in
  `sensitive_exposure_engine.analyse()` for how `suppressed_false_positive`
  findings are handled differently (excluded by default, included on
  request).

## Known limitations

- Four `ExposureLocation` values considered less risky by the confidence
  model (`request_body`, `database_field`, `request_header_processing`, and
  implicitly `unknown`/`cache_entry`/`response_body` when no rule names
  them) fall through to `processing_context_default`
  (`legitimate_processing`) for **any** category not already covered by an
  earlier rule. A new sensitive category added without a corresponding
  category-specific rule silently inherits this default rather than
  `uncertain` — reviewers extending the taxonomy should add an explicit rule
  for any category that should not default to "legitimate."
- Policy rules are evaluated independently per finding; there is no
  cross-finding reasoning (e.g. "this field is usually processing-only but
  this specific request also matched three other unsafe signals").
- `environments` and `sensitivity_levels` dimensions exist in the schema but
  no current rule uses them — there is no environment-specific policy yet
  (e.g. treating `staging`/`dev` more leniently than `production`).
- The rule table is a flat, first-match-wins list; it does not support
  weighted/multi-rule combination or negation (e.g. "unsafe unless X").
