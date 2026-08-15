# Root-Cause Evaluation Results

> **PRELIMINARY / DEVELOPMENT-SET EVALUATION**
>
> **NOT THE FINAL INDEPENDENT HELD-OUT THESIS EVALUATION**

Source: `.codex-runtime/thesis_eval_metrics.json`  
Method: deterministic **signal-overlap ranker** on labelled scenarios (`root_cause_scenarios_v2.yaml`). Cause-specific signals weighted above generic redaction-gap signals. Rankings are computed — **not** hand-filled `predicted_top1`. Not a substitute for full DB-backed `causality_engine.analyse_incident`.

## Aggregate (36 scenarios)

| Metric | Value |
|---|---|
| Top-1 correct | 30/36 = **83.3%** |
| Top-3 correct | 36/36 = **100%** |
| Component localisation | 34/36 = **94.4%** |

## Failure analysis (all Top-1 misses)

| Scenario | Expected Top-1 | Actual Top-1 | Why |
|---|---|---|---|
| RC-H01 | unsafe_request_header_logging | missing_redaction_rule | Only generic redaction-gap signals; no header-specific evidence |
| RC-H02 | unsafe_response_body_logging | unsafe_request_body_logging | Body-log cluster outweighs single response signal |
| RC-H03 | query_string_logging | unsafe_request_header_logging | Strong Authorization/header signals dominate weak query signal |
| RC-H04 | debug_logging_enabled | proxy_log_overcollection | Proxy overcollection cluster dominates sparse debug signal |
| RC-H05 | secret_in_configuration | apm_agent_capture | APM signals outrank sparse config-scan hit |
| RC-H06 | error_handler_serialisation | unsafe_report_transformation | Report-transform cluster dominates single error signal |

Misleading signals typically: competing cause-specific clusters, or absense of the expected cause’s distinctive evidence. Confidence behaviour: high-weight wrong clusters produce confident wrong Top-1 while correct cause often remains in Top-3 (coverage 100%).

## Improvement direction

- Prefer exposure-location alignment when ranking competing clusters.
- Require minimum cause-specific evidence before preferring a specialised cause over `missing_redaction_rule`.
- Calibrate confidence downward under multi-cluster ambiguity.

## Interpretation

Top-3 coverage is complete; Top-1 is imperfect on deliberately ambiguous hard cases. Prefer “likely ranked causes with human review” language in thesis claims. Do not equate offline signal ranker scores with production causality-engine accuracy.
