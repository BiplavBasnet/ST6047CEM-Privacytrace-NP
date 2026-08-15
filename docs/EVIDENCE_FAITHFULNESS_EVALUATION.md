# Evidence Faithfulness Evaluation

Source: `.codex-runtime/thesis_eval_metrics.json` → `evidence_faithfulness`.

## Method

Each technical claim declares `required` evidence types and `present` / `contradicting` sets.

Statuses:

- **supported** — all required evidence present; no contradicting evidence
- **partially_supported** — some but not all required evidence present
- **unsupported** — no required evidence present (invented file claims count here)
- **contradicted** — contradicting evidence present

Strict evidence faithfulness = supported / total claims.

**Not used:** “supporting_evidence_ids not empty ⇒ 100% faithful”.

## Results

| Metric | Value |
|---|---|
| Total claims | 5 |
| Supported | 2 |
| Partially supported | 1 |
| Unsupported | 1 |
| Contradicted | 1 |
| Strict faithfulness | **0.40** |

### Claim breakdown

| ID | Claim (safe) | Status |
|---|---|---|
| C1 | Authorization header was logged | supported |
| C2 | request_logger.py is implicated | supported |
| C3 | invented_module.py is implicated | unsupported |
| C4 | Deployment preceded first exposure | partially_supported |
| C5 | Exposure was already masked | contradicted |

## Takeaway

Invented source-location claims fail. Partial chronological claims without full service/order evidence stay partially supported. Contradicted masking claims are never counted as supported.
