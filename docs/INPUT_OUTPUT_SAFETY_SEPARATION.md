# Input vs. Output Claim Safety Separation

**Phase:** P (core engine hardening, see `docs/CORE_ENGINE_BASELINE_AUDIT.md`)

This document explains a distinction that is easy to blur but load-bearing for
PrivacyTrace-NP's safety model: **ingested evidence** (what a scanner, SIEM,
integration, or Live Monitor event *says*) and **PrivacyTrace-generated
output** (what PrivacyTrace itself *asserts* in a report, alert summary, or AI
explanation) are safety-checked by different rules, for different reasons.

## The problem this separation fixes

Before this phase, several ingestion-side validators
(`scanner_evidence_schema.py`, `scanner_mapping_service.py`,
`scanner_safety_service.py`, `scanner_validation_service.py`,
`integration_validation_service.py`, `live_monitor_safety_service.py`)
independently maintained their own lists of "overclaim" or "forbidden wording"
phrases — e.g. `"confirmed breach"`, `"attacker accessed"` — and **rejected
the entire finding, event, or import** outright if that wording appeared
anywhere in an externally-supplied text field (a scanner's `explanation`, a
SIEM message, a Live Monitor log line).

This is wrong for input evidence. A source scanner's own explanation, a raw
log line, or a SIEM alert message is **a quote of what that external system
said**, not a claim PrivacyTrace is making. If a third-party scanner reports
`"Secret scanner confirmed breach of API key in commit abc123"`, rejecting
that finding because it contains the phrase "confirmed breach" means
PrivacyTrace silently drops real, attributable evidence instead of importing
it and reasoning about it under human review. The wording itself is not
dangerous — it is data about what was observed. What *is* dangerous is
PrivacyTrace echoing that same certainty as **its own conclusion** in
generated output (a report, an alert summary, an AI remediation explanation)
without evidence to support it.

## The two policies

### 1. Input evidence safety — `app/services/input_evidence_safety_service.py`

Governs data coming **into** PrivacyTrace from scanners, SIEM/integration
events, Live Monitor events, and manual evidence uploads. Its job is to keep
ingestion safe and bounded, not to police the *wording* of what was observed:

- **Size limits** — `MAX_TEXT_FIELD_LENGTH`, `MAX_PAYLOAD_SERIALIZED_BYTES`,
  `MAX_PAYLOAD_DEPTH`, `MAX_PAYLOAD_KEYS` reject payloads/text that are too
  large or too deeply nested to safely process (a legitimate hard-reject: an
  oversized payload is a resource-exhaustion / parsing risk regardless of what
  it says).
- **Schema/encoding validity** — malformed encoding or non-JSON-serialisable
  structured payloads are rejected before they reach downstream services.
- **Sensitive-value masking, not rejection** — raw secrets (API keys,
  passwords, JWTs, card numbers, phone numbers, etc.) found inside input text
  or structured payloads are masked in place via
  `scanner_safety_service.remask_string` / `sanitize_payload`. The event or
  finding is still imported; only the raw value is redacted.
  Structural/format problems (oversized payload, unmasked hard-fail-safe
  patterns after remasking) can still cause a masked/rejected result — see
  the module for the exact precedence.
- **No wording-based rejection.** `contains_overclaim_wording()` exists as a
  *diagnostic* helper only — for surfacing "this source described this as
  certain" as metadata a human reviewer might want to see — and is never
  wired into any accept/reject decision.

Every ingestion call site's docstring/comments were updated to state this
explicitly: `scanner_evidence_schema.py`, `scanner_mapping_service.py`,
`scanner_safety_service.py`, `scanner_validation_service.py`,
`integration_validation_service.py`, and `live_monitor_safety_service.py` all
now document that certainty/blame wording from an external source is
*accepted as input evidence*, and that these modules only reject or mask for
size, malformed structure, or raw secret material — never for phrases like
"confirmed breach".

### 2. Output claim safety — `report_safety_service.py`, `ai_output_safety_service.py`, `app/rules/llm_safety_rules.yaml`

Governs text **PrivacyTrace itself generates** — final report narrative
sections, alert summaries, and LLM-produced root-cause/remediation
explanations. This is where overclaim phrases are actively blocked, because
here they *would* be PrivacyTrace's own unsupported conclusion, not a quoted
observation:

- `app/rules/llm_safety_rules.yaml`'s `overclaim_phrases` (includes
  `"confirmed breach"`, `"attacker accessed data"`, and other
  certainty/blame phrases) drives `safe_replacements` that swap an overclaim
  phrase for a hedged equivalent (e.g. `confirmed breach` →
  `privacy incident under review`) before generated text is shown to a user.
- `report_safety_service.FORBIDDEN_OVERCLAIM_REPLACEMENTS` performs the same
  substitution for report narrative sections built outside the LLM path.
- `ai_output_safety_service.FORBIDDEN_OUTPUT_PHRASES` hard-blocks an AI
  remediation suggestion from shipping if it still asserts an overclaim
  phrase as its own conclusion after sanitisation.

None of these three modules touch ingestion; they only run on text
PrivacyTrace is about to display or persist as its own generated narrative.

## Why this split is safe

| | Ingested evidence | PrivacyTrace-generated output |
|---|---|---|
| Certainty wording (e.g. "confirmed breach") | Accepted — it's a quote/observation | Rejected/rewritten — it would be PrivacyTrace's own unsupported claim |
| Oversized/malformed payload | Rejected | N/A (PrivacyTrace controls its own output size) |
| Raw secret value | Masked, not rejected | Never generated in the first place (PrivacyTrace never echoes raw values into narrative) |

The asymmetry is intentional: PrivacyTrace must be a faithful, complete
recorder of what external systems reported (so analysts can act on real
evidence), while remaining conservative and hedged in anything it says on its
own authority (so it never manufactures a false sense of certainty).

## Tests proving the separation

- `app/tests/test_phase11_85_scanner_bridge_safety.py::test_finding_explanation_with_certainty_wording_is_imported_not_rejected` —
  a scanner finding whose `explanation` field contains "confirmed breach"
  wording is imported (`status in {"accepted", "partial"}`), not rejected.
- `app/tests/test_phase11_8_universal_integration.py::test_certainty_wording_alone_is_accepted_as_input_evidence` —
  a Universal Integration Gateway event whose `message` contains certainty
  wording is accepted (`status_code == 200`, `status == "accepted"`,
  `safety_status == "safe"`).
- `app/tests/test_phase_live_privacy_monitor_safety.py::test_narrative_wording_alone_is_accepted_as_input_evidence` —
  a Live Monitor event with overclaim wording in its log message is accepted,
  not rejected.
- `app/tests/test_phase_live_privacy_monitor_safety.py::test_narrative_wording_with_sensitive_value_is_masked_not_rejected` —
  overclaim wording *combined with* a raw sensitive value in the same event
  results in the sensitive value being masked and the event still being
  accepted; the wording itself is never the reason for any rejection.
- Output-side coverage (pre-existing, extended): the LLM safety rules test
  suite and `ai_output_safety_service`/`report_safety_service` unit tests
  confirm a PrivacyTrace-generated explanation asserting "confirmed breach"
  as its own conclusion is rewritten/blocked before being shown to a user.

## Known limitations

- `contains_overclaim_wording()` in `input_evidence_safety_service.py` is a
  best-effort phrase list, not a semantic classifier; it is diagnostic-only
  and never gates ingestion, so its false negatives/positives have no safety
  impact today. If a future feature wants to *surface* "this source used
  strong certainty language" to a reviewer, this is the hook to build on.
- The size/depth/key-count limits are fixed constants tuned by inspection,
  not derived from a measured attack model; see
  `docs/LIMITATIONS_AND_FUTURE_WORK.md`.
- Some ingestion paths still reject on Pydantic schema limits (e.g. a
  `message` field's `max_length`) before `input_evidence_safety_service` or
  the service-level masking logic ever runs. This is intentional (a
  request that violates the wire schema should fail fast) but means the
  "masked, not rejected" behaviour only applies to payloads that are within
  schema bounds; a schema-level size violation is still a hard 422 reject.
  See `test_rejected_ingestion_is_audited_safely` in
  `test_phase11_8_universal_integration.py`.
