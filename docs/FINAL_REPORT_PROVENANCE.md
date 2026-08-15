# Final Report Provenance

`FinalReportMetadata` carries `report_version` (maximum persisted version + 1), policy versions, evidence snapshot, and exact lifecycle references through review, diagnosis, action, implementation, optional patch, test, controlled retest, FixVerification, and VerificationOutcome.

The report anchors on one current `VerificationOutcome`, or reports a validated current prefix as draft. Stored references are traversed and checked for incident ownership/current status; competing branches are never combined. Missing, stale, insufficient, or mismatched chains remain explicitly blocked. Every final export creates an immutable `Report` row rather than rewriting history.
