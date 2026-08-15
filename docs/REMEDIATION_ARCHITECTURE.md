# Remediation Architecture

Authoritative path: RootCauseAnalysis → bound ReviewDecision → RemediationDiagnosis → RemediationAction → RemediationImplementationRecord → applicable RemediationTestExecution → matching ControlledRetest → FixVerification → VerificationOutcome → eligible optional learning. A PatchProposal exists only for controlled-patch implementations.

Diagnosis is deterministic by default; optional AI enrichment is advisory, validated, and falls back truthfully. The controlled patch path is an allowlisted local demo fixture, not a general patch engine or production automation.
