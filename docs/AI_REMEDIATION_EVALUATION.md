# AI Remediation Evaluation

## Metrics (controlled scenarios)

- Primary remediation accuracy
- Component targeting accuracy
- Exact source localisation accuracy (when ground truth exists)
- Unnecessary-change rate
- Human acceptance / accept-with-edit / rejection rates
- Test-plan adequacy
- Raw-value leakage count (target 0)
- Unsupported-code-claim count (target 0)
- Unsafe-remediation count (target 0)

## Method

Use labelled fixtures with known correct remediation class. Do not score success merely because a category appears somewhere without respecting primary selection.

See also: `FINAL_EVALUATION_RESULTS.md`.
