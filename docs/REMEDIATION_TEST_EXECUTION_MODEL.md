# Remediation Test Execution Model

Sandbox/profile tests persist as `RemediationTestExecution` (`execution_id`, profile, exit codes, safe summaries). Execution is gated by `ai_remediation:review` and requires an approved remediation/patch chain where the controlled-patch path applies.

See `sandbox_test_execution_service` and `docs/VERIFIED_FIX_VALIDATION.md`.
