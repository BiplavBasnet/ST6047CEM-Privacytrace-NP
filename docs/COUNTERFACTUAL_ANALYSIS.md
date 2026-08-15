# Counterfactual Analysis

## Purpose

Counterfactual analysis asks how the existing rule-based root-cause ranking
changes when evidence is removed. It is not proof of causation and does not
produce calibrated probability.

## Method

For the selected stored root cause, the service:

1. Recalculates the baseline score and rank using the current rule set.
2. Removes each matched supporting evidence item and recalculates.
3. Tests contradictory and unrelated evidence separately.
4. Labels duplicate evidence removal without allowing duplicates to increase a
   rule's binary signal weight.
5. Excludes fixed-log and fixed-scan retest evidence from original-cause
   support.
6. Produces a deterministic greedy approximation of a minimal evidence set
   when the selected cause is ranked first.

Runs are capped at 25 supporting evidence items. An input fingerprint makes an
identical rerun idempotent for the same root cause and rule-set version.

## Stability and Evidence Roles

Stability levels are `stable`, `moderately_stable`, `fragile`, and
`insufficient_evidence`.

Evidence roles are `decisive`, `strong_support`, `weak_support`,
`redundant`, `irrelevant`, `contradictory`, and `unclassified`.
A ranking change or score reduction of at least 0.20 marks the result fragile.
These thresholds are rule-analysis labels, not statistical confidence.

## API

- `POST /incidents/{incident_id}/counterfactual-analysis`
- `GET /incidents/{incident_id}/counterfactual-analysis`
- `GET /counterfactual-analysis/{analysis_id}`
- `GET /root-causes/{root_cause_id}/counterfactual-analysis`

Every response carries the disclaimer:

> This is rule-based counterfactual analysis and not proof of causation.

## Limitations

The minimal evidence set uses a greedy approximation rather than exhaustive
subset search. Results depend on the current deterministic root-cause rules
and available provenance; they do not establish real-world causation.
