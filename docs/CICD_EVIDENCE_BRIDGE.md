# CI/CD Evidence Bridge

CI/CD evidence is represented as structured supporting evidence for root-cause analysis. It is not a full external CI/CD testbed.

## Backend Files

- Model: `backend/app/models/cicd_evidence.py`
- Service: `backend/app/services/cicd_evidence_service.py`
- Router: `backend/app/routers/cicd_evidence_router.py`
- Schema: `backend/app/schemas/cicd_evidence_schema.py`

## Supported Evidence Types

- `pipeline_run`
- `deployment_event`
- `commit_metadata`
- `changed_files`
- `security_scan_result`
- `test_result`
- `rollback_event`
- `configuration_change`
- `release_metadata`

## Safety Boundaries

CI/CD evidence stores safe summaries, hashes, references, changed-file paths, and metadata. It must not store source-code contents, credentials, raw environment files, private repository tokens, or secrets.
