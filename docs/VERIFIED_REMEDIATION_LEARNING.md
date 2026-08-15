# Verified Remediation Learning

## Wording

Use: **“Verified outcome-informed remediation ranking.”**  
Do not use: “self-learning AI.”

## Inputs to ranking

- root-cause category match
- exposure-location match
- sensitive-type match
- component match
- verified historical success / failure
- human edits (approved payload)
- known risks

## Non-goals

- Do not modify the underlying LLM automatically.
- Do not silently change policy versions.
- Do not let rejected or unverified remediations raise success counts.

## Implementation

Service: `verified_outcome_learning_service`  
Hint API: `playbook_ranking_hint(db, …)` / `ranking_influence_for_similar()`  
Storage: `VerifiedRemediationCase`, `RemediationPlaybook` (PostgreSQL).
