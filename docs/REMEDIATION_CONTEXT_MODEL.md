# Remediation Context Model

Service: `remediation_context_service.build_remediation_evidence_package`.

## Included (safe)

Incident id, sensitive-data category/type/level, exposure location, exposure-policy decision, masked summaries, affected service/endpoint/environment, safe correlation ids, first/last seen, occurrence count, likely root-cause candidate/category/component, causal evidence strength, supporting/contradicting/missing evidence, deployment/scanner/code-location references when present, limitations.

## Excluded

Raw sensitive values, tokens, JWTs, API keys, phone/bank identifiers, passwords, secrets, private keys, complete `.env` contents, repository credentials.

Raw-value leakage target for AI input: **0**.
