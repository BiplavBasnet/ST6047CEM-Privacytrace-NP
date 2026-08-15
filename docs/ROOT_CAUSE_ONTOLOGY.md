# Root-Cause Ontology (Phase L / brief Section 17)

## Purpose
`backend/app/rules/root_cause_ontology.yaml` is a small, declarative catalogue of
recognised root-cause **categories** — for example "unsafe request-header
logging" or "hardcoded secret exposure". It exists to give the causality
engine a transparent, auditable way to say "these structured exposure facts
are consistent with this category" without inventing new scoring logic per
category and without ever claiming a confirmed cause.

The ontology does **not** decide a root cause on its own. It only provides a
small, bounded boost on top of the existing signal-based scoring in
`root_cause_rules.yaml`, and every application of that boost is recorded so a
human reviewer can see exactly why it fired.

## Category shape
Each category in `root_cause_ontology.yaml` has:

| Field | Meaning |
|---|---|
| `id` | Stable category id, e.g. `unsafe_request_header_logging`. |
| `display_name` | Human-readable label. |
| `applicable_sensitive_types` | Sensitive-type family this category applies to (e.g. `bearer_token`, `jwt_token`). |
| `applicable_exposure_locations` | Exposure locations this category applies to (e.g. `request_header_log`). |
| `maps_to_root_causes` | Which `root_cause_rules.yaml` `likely_root_cause` id(s) this category can boost. |
| `boost_weight` | Bounded score added to the candidate's `base` score when the category matches (typically 0.03–0.08). |
| `max_applications` | Maximum number of independent exposure facts counted per category per candidate (prevents one category from dominating the score). |
| `reason` | Safe, human-readable explanation stored on every `score_breakdown` entry produced by this category. |

Current categories: `unsafe_request_header_logging`,
`unsafe_request_body_logging`, `missing_redaction_rule`,
`debug_logging_enabled`, `hardcoded_secret_exposure`,
`access_control_gap`, `sensitive_error_response_exposure`,
`misconfigured_downstream_sink`, `suspicious_dependency`.

## Loader service
`backend/app/services/root_cause_ontology_service.py` loads and caches the
YAML file (`load_ontology()`, `lru_cache`-backed), exposes
`categories_for_root_cause(likely_root_cause)` to look up which categories can
boost a given candidate, and `category_matches_fact(category, sensitive_type,
exposure_location)` to test one structured exposure fact (see
`docs/ROOT_CAUSE_EVIDENCE_MODEL.md`) against a category's applicability
rules.

## Wiring into the causality engine
`causality_engine._apply_ontology_boost(ctx, cause_rule)`:

1. Looks up the categories mapped to the candidate's `likely_root_cause`.
2. For each category, counts how many of `ctx.exposure_facts` independently
   match it (capped at `max_applications`).
3. If at least one fact matches, adds `boost_weight` to the candidate's base
   score and appends a `score_breakdown` entry:

```json
{
  "signal_name": "ontology_boost:unsafe_request_header_logging",
  "match_type": "ontology_category_match",
  "matched": true,
  "weight": 0.08,
  "evidence_ids": ["EVD-..."],
  "reason": "Structured exposure facts show a token-family value observed at a request-header logging location, which correlates with this ontology category.",
  "ontology_category_id": "unsafe_request_header_logging",
  "ontology_version": "1.0"
}
```

This entry is fully auditable in `RootCauseScore.score_breakdown` and in the
`GET /incidents/{incident_id}/trace` / evidence-graph responses — the boost
is never hidden inside an opaque total.

## Wording discipline
Every ontology `reason` uses "supports"/"correlates with" language. The
ontology never claims a category "proved", "confirmed", or "guaranteed" the
cause — see `root_cause_evidence_strength_service.FORBIDDEN_REPLACEMENTS` for
the enforced safe-wording substitutions applied elsewhere in the pipeline.

## Versioning
`ontology.version` (top-level `version:` key in the YAML) is folded into
`causality_engine.compute_rules_version()`, so an old analysis's
`rules_version` field shows whether it was produced under a different
ontology version than the one currently loaded (see
`docs/ROOT_CAUSE_ANALYSIS_VERSIONING.md`).
