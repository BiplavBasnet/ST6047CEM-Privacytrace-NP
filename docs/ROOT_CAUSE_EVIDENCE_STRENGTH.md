# Root Cause Evidence Strength

Root-cause confidence and evidence strength are calculated on the backend by `backend/app/services/root_cause_evidence_strength_service.py`.

See `docs/ROOT_CAUSE_EVIDENCE_MODEL.md` for the full field-by-field model,
including how structured exposure facts (Phase L) and the ontology (Phase O
categories) feed causal scoring.

## Causal vs. post-remediation validation (Phase M)

As of Phase M, "evidence strength" is two separately-computed results, not
one mixed score:

- **Causal evidence strength** (`causal_evidence_strength`) — how strong the
  *pre-remediation* technical case is. Computed only from structured
  exposure facts, trace/deployment/scanner correlation, and contradictions.
  It **never** reads remediation actions, retest evidence, fix verification,
  or human review approval, so a later successful fix can never retroactively
  inflate it (and a failed one can never deflate it).
- **Post-remediation validation** (`post_remediation_validation`) — a
  separate status/score for what happened *after* a cause was identified:
  remediation recorded, retested, verified, human-approved.

`calculate_evidence_strength(db, incident_id)` returns both nested in full,
plus top-level `confidence_*`/`evidence_strength_*` fields that are sourced
**only** from the causal result, for backward compatibility with existing
callers.

## Output

The backend response includes: likely cause, top-level confidence/evidence-strength fields (causal-only), a confidence cap, limitations, supporting evidence, contradicting evidence, missing evidence, matched signals, negative signals, recommended next evidence, and the nested `causal_evidence_strength` / `post_remediation_validation` objects.

## Causal strength levels (`causal_evidence_strength.causal_strength_level`)

- **Weak**: one symptom source, live alert only, or missing service/endpoint context.
- **Medium**: multiple correlated symptoms, repeated alert, matching service and endpoint, or timeline correlation.
- **Strong**: deployment, configuration, scanner, CI/CD, or technical evidence linked to the affected component.
- **Very strong**: multiple *independent* technical evidence sources (deployment, configuration, changed-file, or scanner) with no unresolved contradictions and complete service/endpoint/time context — achievable purely from pre-remediation technical evidence, never from remediation/review/retest.

## Post-remediation validation status (`post_remediation_validation.validation_status`)

`not_started` → `remediation_recorded` → `retested` → `verified_passed` /
`verified_failed`, plus `review_approved` tracked separately.

## Safety

The system uses "likely cause", "supporting evidence", "confidence level", and "missing evidence". It must not present a cause as proven or a fix as guaranteed.
