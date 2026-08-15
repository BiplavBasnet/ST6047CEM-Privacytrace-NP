# Remediation Action Workflow

Remediation actions are persisted human-owned records, not simulated UI state.

## Backend Files

- Model: `backend/app/models/remediation_action.py`
- Service: `backend/app/services/remediation_action_service.py`
- Router: `backend/app/routers/remediation_action_router.py`
- Schema: `backend/app/schemas/remediation_action_schema.py`

## Rules

- A remediation action can only be created after an approved Human Review.
- Required fields are action description, affected component, owner, status, priority, and retest requirement.
- Statuses that satisfy workflow completion are `awaiting_retest` and `completed`.
- Completed actions require completion notes.
- Every create/update is recorded in the audit log.
- PrivacyTrace-NP records remediation work; it does not claim to change production systems.
- Raw sensitive values and unsafe overclaim wording are sanitized before storage.

AI remediation remains optional guidance and does not approve root cause, save actions automatically, verify fixes, or close incidents.
