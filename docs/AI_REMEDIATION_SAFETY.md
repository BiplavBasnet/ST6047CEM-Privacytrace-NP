# AI Remediation Safety

Services: `remediation_ai_safety_service`, `remediation_repository_safety_service`, `patch_safety_service`.

## Input safety

Secret scan/redaction; reject private keys/credentials/raw tokens/raw `.env`; minimise source context; allowlisted repository paths only.

## Output safety

Reject raw sensitive values, unsupported certainty phrases (`proven cause`, `guaranteed fixed`, `AI fixed`, `production fix applied`, …), invented source claims when `exact_source_location_known=false`, production execution instructions, destructive commands.

## Code context

`remediation_code_context_service` returns the smallest allowlisted excerpt or `context_available=false`.
