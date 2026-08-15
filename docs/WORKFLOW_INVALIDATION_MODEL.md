# Workflow Invalidation Model

When root-cause evidence changes or a newer analysis supersedes an older one:

1. `RootCauseAnalysis` is marked stale / non-current.
2. Bound `ReviewDecision` rows lose `progression_valid` (`progression_invalid_reason` set).
3. Downstream `RemediationDiagnosis` rows get `derived_from_stale_analysis=true` and `workflow_status=stale`.
4. Downstream `RemediationAction` rows get `requires_revalidation=true`.

Operators must re-analyse and re-submit review before remediation can progress again.

`GET .../workflow-state` surfaces `blocked_reasons` when review/analysis provenance is invalid.
