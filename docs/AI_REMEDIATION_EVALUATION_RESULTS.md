# AI Remediation Evaluation Results

> **PRELIMINARY / DEVELOPMENT-SET EVALUATION**
>
> **NOT THE FINAL INDEPENDENT HELD-OUT THESIS EVALUATION**

Source: `.local_eval_runtime/thesis_eval_metrics.json` → `ai_remediation`  
Scenarios: `backend/app/evaluation_data/ai_remediation_scenarios.yaml` (15)

## Accuracy rule

Remediation is correct only when the **structured remediation category** matches ground truth (e.g. `request_header_redaction`). Keyword presence in free text is **not** sufficient.

Unacceptable categories include: disable authentication, disable all logging, ignore finding, rotate token only without fixing the exposure path.

## Aggregate

| Metric | Value |
|---|---|
| Scenario count | 15 |
| Primary remediation accuracy | **86.7%** |
| Component-targeting accuracy | **86.7%** |
| Source-localisation accuracy | **20.0%** |
| Unsafe remediation count | **2** |
| Unsupported source-claim count | **2** |
| Test-plan adequacy | **80.0%** |

## Test-plan adequacy criteria

A plan scores adequate when it includes:

1. same component under test;
2. synthetic sensitive value;
3. original exposure path;
4. negative assertion (raw value absent);
5. positive assertion (expected masking if applicable);
6. preservation of required functionality.

## Playbook vs AI

Primary category selection is playbook/deterministic. AI may adapt wording. Evaluation scores category match, not prose similarity. See `AI_AND_PLAYBOOK_RESPONSIBILITY_MODEL.md`.
