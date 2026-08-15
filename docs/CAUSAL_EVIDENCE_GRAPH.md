# Causal Evidence Graph (Phase O)

## Endpoint
`GET /incidents/{incident_id}/evidence-graph` →
`backend/app/services/evidence_graph_service.build_incident_evidence_graph`.
Returns privacy-safe `nodes`, `edges`, and a `disclaimer`.

## Wording discipline
> "This graph shows evidence relationships and ranked likely causes for
> review; edges describe what supports or correlates with a candidate —
> never that a candidate was proved to have caused the incident. Final
> disposition requires human review."

Every edge reason and relationship type uses "supports"/"correlates with"
language. The graph never claims a candidate was "proved caused by" or
"confirmed".

## Edge shape
Every edge (`EvidenceGraphEdge` schema) now carries, in addition to the
original `source`/`target`/`relationship` fields kept for backward
compatibility:

| Field | Meaning |
|---|---|
| `relationship_type` | One of the typed relationships below. |
| `strength` | 0–1 float. For structural edges this is a fixed value (e.g. `1.0` for "this evidence item exists on this incident"); for causal edges it is the matched signal's rule weight normalised into 0–1 (`_signal_strength`). |
| `relationship_reason` | The exact safe reason text from the matched `root_cause_rules.yaml` signal, ontology-boost category, or a structural description. |
| `correlation_rule_id` | The `signal_name` (or `ontology_boost:<category_id>`) that produced the edge, or `null` for purely structural edges. |

## Relationship types

| `relationship_type` | Meaning | Source |
|---|---|---|
| `DETECTED_IN` | Structural: evidence exists on the incident, was normalized into an event, or a masked detection was extracted from it. | Timeline construction. |
| `SUPPORTS_CANDIDATE` | A matched signal (or ontology-category boost) supports this likely cause. | `score_breakdown` entries where `matched=True` and not a contradiction/time signal, plus the legacy aggregate `supported_by` edge. |
| `CONTRADICTS_CANDIDATE` | A matched contradiction signal weakens this likely cause. | `score_breakdown` entries with `is_contradiction=True`, plus the legacy aggregate `contradicted_by` edge. |
| `FIRST_APPEARED_AFTER` | Deployment-before-incident timing signal. | `deployment_before_incident_within_minutes` match type. |
| `TEMPORALLY_CORRELATES` | Access-event-near-incident or stale-evidence timing signal. | `access_event_near_incident_minutes` / `old_evidence_outside_time_window` match types. |
| `REQUIRES_REVIEW` | Structural: every likely-cause ranking requires human review before action. | Always added per ranked cause. |
| `RELATED_TO` | Fallback for any structural relationship not otherwise classified. | Defensive default. |

## Per-signal edges (the Phase O addition)
`_causal_edges_for_cause(cause)` walks a ranked cause's `score_breakdown`
(every signal the causality engine evaluated — see
`docs/ROOT_CAUSE_EVIDENCE_MODEL.md` — including ontology-boost entries) and,
for every **matched** signal, creates one edge per supporting/contradicting
evidence id, carrying that signal's exact `reason` and `signal_name` as
`correlation_rule_id`. This replaces the previous generic "supported_by" /
"contradicted_by" edges (still emitted once per cause for backward
compatibility) with fully traceable, per-signal edges — a reviewer can see
*which specific signal* (e.g. `exposure_fact_token_at_header_location` or
`ontology_boost:unsafe_request_header_logging`) produced each connection.

## Example edge
```json
{
  "source": "RCA-...",
  "target": "EVD-API-1",
  "relationship": "supports_candidate",
  "relationship_type": "SUPPORTS_CANDIDATE",
  "strength": 0.286,
  "relationship_reason": "A structured exposure fact recorded a token-family value at a request-header logging location, which supports this candidate.",
  "correlation_rule_id": "exposure_fact_token_at_header_location"
}
```

## Node types
`incident`, `evidence`, `normalized_event`, `detection`, `root_cause` — sorted
in that order in the response, with `id` as the tiebreaker.

## Deduplication
Edges are de-duplicated on `(source, target, relationship_type,
correlation_rule_id)`, so the same signal firing for the same evidence id is
never listed twice, but distinct signals supporting the same evidence/cause
pair each keep their own edge.
