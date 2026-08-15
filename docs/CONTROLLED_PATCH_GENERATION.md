# Controlled Patch Generation

Services: `controlled_patch_service`, `patch_safety_service`.

## Preconditions

1. Diagnosis status `accepted` or `accepted_with_edits`
2. `exact_source_location_known`
3. Proposed change present
4. Patch safety validation passes

## Allowed

Allowlisted local repository context, temporary sandbox workspace under `remediation_sandbox_root`, draft guidance file.

## Forbidden

Production modification, `git push`, remote merge, direct deployment, AI-generated shell execution, `.env`/private-key edits, disabling auth/masking/audit.
