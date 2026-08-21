/** User-facing labels. Backend enum/schema names stay unchanged. */

const LABELS: Record<string, string> = {
  controlledretest: "Retest the fix",
  controlled_retest: "Retest the fix",
  fixverification: "Verify the fix",
  fix_verification: "Verify the fix",
  root_cause: "Likely cause",
  root_cause_analysis: "Likely cause",
  evidence_completeness: "Evidence available",
  contradicting_evidence: "Evidence against this cause",
  human_review: "Human review",
  final_report: "Final report",
  testexecution: "Allowlisted test",
  test_execution: "Allowlisted test",
  verificationoutcome: "Verification outcome",
  verification_outcome: "Verification outcome",
  pending_verification: "Pending verification",
  pending_unassigned: "Pending assignment",
  partially_verified: "Partially verified",
  manual_review: "Manual review",
  verified: "Verified",
  rejected: "Rejected",
  linked_to_incident: "Linked to incident",
  dismissed_false_positive: "Dismissed",
  under_review: "Under review",
  security_analyst: "Security Analyst",
  devsecops_engineer: "DevSecOps Engineer",
  organisation_admin: "Organisation Admin",
  platform_admin: "Platform Admin",
};

export function userFacingLabel(value: string | null | undefined): string {
  if (!value) return "—";
  const key = value.toLowerCase().replace(/[\s-]+/g, "_");
  return LABELS[key] ?? value.replace(/_/g, " ");
}
