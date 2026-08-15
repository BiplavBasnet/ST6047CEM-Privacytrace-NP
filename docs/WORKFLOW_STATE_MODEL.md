# Workflow State Model

PrivacyTrace-NP uses `backend/app/services/incident_workflow_service.py` as the single backend source of truth for incident stage readiness, completion, blocked reasons, and next action.

## Endpoint

`GET /incidents/{incident_id}/workflow-state`

## Stages

1. Overview
2. Root Cause & Traceability
3. Human Review
4. Remediation
5. Fix Verification
6. Final Report

## Core Rules

- Overview is available when the incident exists.
- Root Cause & Traceability requires linked alert, detection, scanner, CI/CD, or evidence data.
- Human Review requires completed root-cause evidence strength.
- Remediation requires a final approved human-review decision.
- Fix Verification requires the current approved diagnosis action, a persisted implementation, a passed safe allowlisted test, and an explicit completed controlled retest with matching server-backed dimensions. Imported `fixed_log` or `fixed_scan` evidence alone does not unlock verification.
- Final Report readiness is derived from workflow facts and report-readiness checks.

The frontend consumes this state through `api.getWorkflowState()` and should not independently decide readiness.
