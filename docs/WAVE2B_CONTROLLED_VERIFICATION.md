# Wave 2B Controlled Verification

Date: 2026-08-13

The normal remediation path now persists a human-attributable implementation
record for `controlled_patch`, `manual`, or `external_configuration_change`.
Controlled patch application creates its implementation record automatically;
manual and configuration changes use the authenticated lifecycle endpoint.

Allowlisted test execution derives its action, implementation, patch, and
workspace from persisted references. It persists `running` and final states,
stores only a masked summary and leakage count, and never executes caller- or
AI-supplied commands.

A controlled retest is created only through the authenticated controlled-retest
endpoint. Its supplied synthetic output is evaluated transiently by the shared
Sensitive Exposure Engine; raw input is not stored. The record keeps masked
findings, exact ancestor references, original detection, matching dimensions,
timestamps, and the decisive post-change exposure result.

Fix verification now requires the current approved exact chain, completed
implementation, applicable passed safe test, and controlled retest. Dimension
mismatch is inconclusive. A matching retest with an unsafe engine result fails;
a matching clean result passes. The same transaction creates or reuses the fix
verification, verification outcome, audit history, and learning eligibility.
Only a complete current passed exact-chain outcome may affect learning.

Migration `028_controlled_retest_verification` is additive and PostgreSQL-only.
It creates the implementation and controlled-retest tables and adds nullable
legacy-compatible exact-chain references and idempotency constraints.
