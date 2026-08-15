# RBAC Governance Model

**Module:** `permission_service` + `require_permission` router dependencies.

Sensitive writes (remediation approve, patch approve/apply, sandbox test run, fix verification, preventive-control approve) require role permissions beyond the frontend. Viewers lack `ai_remediation:review`, `incident:review`, `fix:verify`, and similar write permissions — HTTP returns 403.

See also `docs/PHASE11_6_AUTH_ACCESS_CONTROL.md`.
