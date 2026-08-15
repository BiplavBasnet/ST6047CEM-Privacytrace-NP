# Viva Walkthrough

## One-sentence thesis claim

PrivacyTrace-NP detects unsafe sensitive-data exposure in DFS-style API logs, proposes evidence-grounded likely root causes, and supports **human-governed**, playbook-selected remediation with controlled sandbox verification and durable verified-outcome learning.

## Demo spine (gold standard)

1. Synthetic wallet service logs `Authorization: Bearer SYNTHETIC_TEST_TOKEN_123` via `log_request_headers`.
2. Detection → `bearer_token` / `request_header_log`.
3. Likely cause → `unsafe_request_header_logging` (request logging middleware).
4. Source evidence → `request_logger.py` / `log_request_headers` (no invent without evidence).
5. Playbook primary remediation → redact Authorization before serialisation.
6. Human Edit and Accept (multi-field; `original_ai_payload` preserved).
7. Controlled patch → real unified diff in sandbox; never production; never push.
8. Allowlisted regression → raw token absent from log.
9. Fix verification → “passed based on available controlled retest evidence.”
10. Verified case + playbook counters survive restart (PostgreSQL).

## Language to use / avoid

| Prefer | Avoid |
|---|---|
| Likely root cause | Proven root cause |
| Verified outcome-informed ranking | Self-learning AI |
| Playbook-selected, AI-assisted | AI independently discovered the fix |
| Verification passed based on controlled retest evidence | Permanently fixed / guaranteed secure |

## Key docs

- `GOLD_STANDARD_REMEDIATION_SCENARIO.md`
- `AI_AND_PLAYBOOK_RESPONSIBILITY_MODEL.md`
- `FINAL_EVALUATION_RESULTS.md`
- `LIMITATIONS_AND_FUTURE_WORK.md`
