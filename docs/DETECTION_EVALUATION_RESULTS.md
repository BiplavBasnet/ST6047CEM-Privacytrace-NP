# Detection Evaluation Results

> **PRELIMINARY / DEVELOPMENT-SET EVALUATION**
>
> **NOT THE FINAL INDEPENDENT HELD-OUT THESIS EVALUATION**

Source: `.codex-runtime/thesis_eval_metrics.json`  
Engine: production unified exposure engine  
Dataset: `instance_level_cases_v2.yaml`

## Aggregate

| Metric | Value |
|---|---|
| Dataset size | 335 |
| Positive instances | 128 |
| Negative instances | 207 |
| TP | 132 |
| FP | 20 |
| FN | 0 |
| TN | 184 |
| Precision | 0.8684 |
| Recall | 1.0 |
| F1 | 0.9296 |
| FPR | 0.098 |
| FNR | 0.0 |
| Raw-value leakage | 0 |

Note: TP (132) can exceed positive instance count (128) when multi-type positives yield multiple true detections per instance. Do not treat curated v1 unit-test perfect scores as this corpus.

## Per-type (selected)

| Type | P | R | F1 | Notes |
|---|---|---|---|---|
| phone_number | 1.0 | 1.0 | 1.0 | |
| wallet_identifier | 1.0 | 1.0 | 1.0 | |
| transaction_reference | 1.0 | 1.0 | 1.0 | |
| api_key | 1.0 | 1.0 | 1.0 | |
| password | 1.0 | 1.0 | 1.0 | |
| email_address | 1.0 | 1.0 | 1.0 | |
| jwt | 1.0 | 1.0 | 1.0 | |
| bearer_token | 0.4595 | 1.0 | 0.6296 | **20 FP** drive overall precision down |
| private_key | 1.0 | 1.0 | 1.0 | n=1 TP |

## Unsafe exposure classification

`unsafe_exposure_classification_accuracy` = **0.0909**

**Weak.** Treat as decision-label mismatch needing future work — do not celebrate. Detection of sensitive types is strong; labelling *unsafe exposure* decisions against this corpus is not.

## Takeaway

High recall (1.0) and solid F1 (0.9296) on type detection; precision limited by bearer_token false positives; unsafe-exposure decision accuracy remains a known gap.
