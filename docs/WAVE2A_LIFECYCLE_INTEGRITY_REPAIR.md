# Wave 2A Lifecycle Integrity Repair

Date: 2026-08-13

This repair introduces one governed-remediation permission resolver. A current
transition now requires the exact non-stale root-cause analysis identity,
version and evidence snapshot; its progression-valid approved human review;
and matching descendant references where a diagnosis or action already exists.
Approval and action transitions require an active application user.

Workflow state now traverses stored references from the current analysis and
review. It does not independently select the newest diagnosis, action, patch,
test execution or verification outcome. States are reported as `current`,
`stale`, or `blocked`. New evidence preserves history while marking linked
diagnoses, actions, patches, test executions, outcomes and learning cases stale
and ineligible for current progression.

Migration `027_lifecycle_integrity_foundation` is additive and PostgreSQL-only.
It adds current-RCA and incident/version uniqueness, one canonical action per
diagnosis, verification/learning idempotency indexes, nullable lifecycle
foreign keys with `ON DELETE RESTRICT`, and non-destructive workflow status
columns. Ambiguous legacy duplicate actions are retained as detached historical
rows. Foreign keys are added `NOT VALID` so legacy ambiguity is not rewritten
as invented provenance while new writes are enforced.

The controlled patch implementation remains the allowlisted local gold-fixture
proof of concept. First-create live-alert concurrency, first-class
implementation records, and controlled retests are outside Wave 2A.
