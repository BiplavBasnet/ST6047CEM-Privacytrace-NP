# Unified Context-Aware Sensitive-Data Exposure Engine

Implements steps B–G of the locked implementation order in
`docs/CORE_ENGINE_BASELINE_AUDIT.md`: taxonomy bridge, candidate detection,
exposure policy, confidence/false-positive suppression, a single finding
shape, and one HMAC fingerprint contract.

Step H (see `docs/CORE_ENGINE_BASELINE_AUDIT.md` §H) unifies both detection
call sites onto this engine:

- `detection_service.detect_event` (Evidence Import path) calls
  `sensitive_exposure_engine.analyse()` on the event text, maps
  `unsafe_exposure`/`uncertain` findings to `Detection` rows using the
  finding's own `confidence_score` (never a hardcoded value) and HMAC
  fingerprint (`sensitive_fingerprint_service`, prefix `HMAC-SHA256-V1:`)
  for `raw_value_hash`, and prefers the finding's canonical `sensitive_type`
  over the legacy raw pattern id. `classify_and_persist`'s taxonomy
  side-effects are preserved.
- `live_monitor_service.process_event` (Live Monitor path) calls the same
  `analyse()` entry point and only creates a `PrivacyAlert` for
  `unsafe_exposure`/`uncertain` findings — see `docs/LIVE_PRIVACY_MONITOR.md`
  and `docs/LIVE_ALERT_GROUPING.md`. `live_monitor_safety_service` still runs
  as an independent safety gate (input size / unsafe wording / masked-output
  assertion) alongside the engine, not instead of it.

Both call sites now classify, score, and fingerprint a given value
identically; `test_live_evidence_unified_detector.py` asserts this directly
by feeding the same raw value through both paths. `contextual_detection_
service.py` is unaffected by this change and still runs its own separate
logic (see Limitations).

## Pipeline

```
sensitive_candidate_detection_service.detect_candidates()
    -> sensitive_value_validation_service.validate_candidate()
    -> sensitive_data_taxonomy_service (category/sensitivity)
    -> exposure_location inferred from source_type + context_metadata
    -> sensitive_exposure_policy_service.evaluate()
    -> sensitive_detection_confidence_service.score_confidence()
    -> suppress false positives (drop suppressed_false_positive findings)
    -> masking_service.mask_value() for masked_preview
    -> sensitive_fingerprint_service.fingerprint() (skipped when already masked)
    -> raw value discarded; finding dict returned
```

Entry point: `sensitive_exposure_engine.analyse(source_type=..., text=...,
structured=..., service=..., endpoint=..., environment=..., event_time=...,
context_metadata=..., include_suppressed=False)` returns a list of finding
dicts. It creates no alerts and persists nothing — callers (a router, a Live
Monitor adapter, a batch job) decide what happens with returned findings.

### Candidates (`sensitive_candidate_detection_service.py`)

Two candidate sources, both returning `SensitiveCandidate` (no persistence,
`raw_value` kept only for the calling process):

- **Text regex** — patterns loaded from `app/rules/sensitive_data_rules.yaml`
  plus a small set of additional patterns (`wallet_generic`, `email_generic`,
  `card_number_generic`) that historically only existed hardcoded in
  `live_monitor_safety_service.py`, so evidence-path and live-path free-text
  scanning stay consistent. Overlapping matches are deduplicated, keeping the
  longest span (so `Authorization: Bearer <jwt>` is one candidate, not three).
- **Structured field-name aliases** — a dict of leaf field names (`otp`,
  `verification_code`, `card_number`, `wallet_id`, ...) mapped to a
  `raw_type_hint`, scanned over a flattened structured payload (dict/list, up
  to depth 4). This alias table is intentionally separate from the Nepal
  taxonomy registry's alias/context-term matching.

`DETECTOR_VERSION = "unified_candidate_v1"` is recorded on every candidate.

### Exposure location

`ExposureLocation` (`app/models/enums.py`) distinguishes controlled
processing channels (`request_header_processing`, `request_body`,
`database_field`) from channels that make a raw value durable or widely
readable (`application_log`, `query_string`, `request_header_log`,
`error_message`, `third_party_log`, `cache_entry`, `file_export`,
`webhook_payload`, `ai_prompt_context`, or `unknown`). The engine infers it
from `source_type` (a short channel name the caller passes, e.g.
`"application_log"`, `"request_header"`, `"query_string"`) and an optional
explicit `context_metadata["exposure_location"]` override, or
`context_metadata["logged"]` to mark a header observation as having reached a
log.

### Policy (`sensitive_exposure_policy_service.py` + `app/rules/exposure_policy_rules.yaml`)

`evaluate(taxonomy_type, sensitivity, exposure_location, source_type,
field_name, environment, masking_state, negative_signals)` returns one of the
`ExposureDecision` values (`app/models/enums.py`):

1. `hard_suppress_signals` from validation (e.g. `luhn_failed`,
   `missing_auth_field_context`, `jwt_structure_failed`) short-circuit to
   `suppressed_false_positive` before any location reasoning runs.
2. `masking_state == "masked"` (or an `already_masked_pattern` negative
   signal) short-circuits to `already_safely_masked`.
3. YAML rules are matched top-to-bottom by category/exposure_location/
   source_type/environment/sensitivity/field_name (first match wins):
   sensitive values in `query_string` are always `unsafe_exposure`;
   `AUTHENTICATION_SECRET` values in log-like channels are `unsafe_exposure`,
   in processing-only channels are `legitimate_processing`; `FINANCIAL`/`KYC`/
   `PERSONAL` values in log/export/webhook/AI-prompt channels are
   `unsafe_exposure`; anything left in `request_body`/`database_field`/
   `request_header_processing` defaults to `legitimate_processing`.
4. No matching rule -> `uncertain` (fails closed to human review, never to an
   automatic verdict).

### Confidence (`sensitive_detection_confidence_service.py`)

One deterministic weighted score (`score_confidence`) replacing the
historical mix of a hardcoded `confidence=0.92` link, a raw detector float,
and string confidence labels. Inputs: pattern strength (or a neutral 0.5 for
field-alias-only candidates with no regex confidence), validator score, field
relevance, exposure-location support, policy-decision modifier, normalised
Shannon entropy of the raw value, and a flat per-negative-signal penalty.
Returns `score` (0–1), `level` (`low`/`medium`/`high`/`very_high`), a full
`breakdown` dict per contribution, and `positive_signals`/`negative_signals`.
Same inputs always produce the same output; there is no per-type hardcoded
score anywhere in this module. `ENGINE_VERSION = "confidence_engine_v1"`.

### Fingerprint (`sensitive_fingerprint_service.py`)

One supported method: keyed HMAC-SHA256 over taxonomy type + normalised value
(`fingerprint(value, taxonomy_type) -> {fingerprint, method, version}`),
wrapping `taxonomy_validator_service.hmac_fingerprint` and
`settings.detection_hmac_key`. `FINGERPRINT_METHOD = "hmac_sha256_v1"`.
`is_legacy_sha256(hash)` flags the old unkeyed `sha256:` prefix used by
`detection_service.hash_raw_value` so it is never compared against an HMAC
fingerprint as if equivalent — a plain SHA-256 digest of a predictable,
low-entropy identifier (phone number, account number) is brute-forceable.
Raises `FingerprintUnavailableError` rather than silently falling back to an
unkeyed hash when `DETECTION_HMAC_KEY` is unavailable.

### Finding shape

Returned dicts include: `finding_id`, `sensitive_category`, `sensitive_type`,
`raw_type_hint`, `taxonomy_version`, `sensitivity_level`, `exposure_location`,
`exposure_decision`, `policy_rule_id`, `policy_version`, `policy_reason`,
`confidence_score`, `confidence_level`, `confidence_breakdown`,
`confidence_engine_version`, `positive_signals`, `negative_signals`,
`masked_preview`, `value_fingerprint`, `fingerprint_method`,
`fingerprint_version`, `field_name_safe`, `json_path_safe`,
`source_location`, `source_type`, `pattern_id`, `validator_id`,
`detector_version`, `engine_version`, `service_name`, `endpoint`,
`environment`, `event_time`, `safety_status`
(`safe`/`unsafe`/`requires_review`/`suppressed`), and `limitations`.
**No finding ever contains a `raw_value` key**; this is asserted in code
(`sensitive_exposure_engine._build_finding`) and covered by
`test_unified_exposure_engine.py::test_raw_value_never_present_in_finding_output`.

## Safety

- Raw values exist only inside `analyse()`'s local scope, are never logged,
  never placed on a finding, and never persisted — this module has no
  database dependency at all.
- Field names and JSON paths are sanitised to an allow-listed character set
  before being placed on a finding (`unclassified` otherwise), matching the
  existing `contextual_detection_service._safe_context_label` pattern.
- `context_metadata` passed to `analyse()` is used only to infer exposure
  location; it is never echoed onto a finding.
- Plain SHA-256 is never treated as a stable-comparison fingerprint for any
  taxonomy type in this module.

## Known limitations

- `contextual_detection_service.py` still runs its own separate detection
  logic and has not been unified onto `sensitive_exposure_engine.analyse()`.
  `live_monitor_safety_service.py` also still runs independently as a raw
  safety gate (see above) rather than being replaced by the engine.
- `analyse()` itself remains a pure function over its inputs with no
  database dependency; alerting and persistence (Detection rows, PrivacyAlert
  rows, alert grouping, runtime state) are implemented by the calling
  services (`detection_service.py`, `live_monitor_service.py`,
  `live_alert_grouping_service.py`), not by this module.
- `exposure_location` inference is driven by the `source_type` string and an
  optional explicit override; it does not parse a real HTTP request/response
  object. Callers integrating this engine with an actual request pipeline
  must map their own channel information onto `source_type`/
  `context_metadata["exposure_location"]`.
- The structured field-name alias table
  (`sensitive_candidate_detection_service._FIELD_NAME_ALIASES`) is a fixed
  Python dict, not YAML-configurable like the exposure policy; extending
  taxonomy-type coverage for structured detection currently requires a code
  change.
- Confidence weights and exposure-location/policy modifiers are fixed
  constants tuned by inspection, not empirically calibrated; per AGENT.md,
  they must not be described as calibrated probabilities.
- Only regex patterns already present in `sensitive_data_rules.yaml` plus
  three additional generic patterns are scanned over free text; this does not
  claim complete coverage of every sensitive-value format.
