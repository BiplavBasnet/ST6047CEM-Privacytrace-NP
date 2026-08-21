import type { EvidenceFile } from "../api/client";

export const EXPECTED_EVIDENCE_CATEGORIES = [
  "api_log",
  "runtime_log",
  "semgrep_report",
  "gitleaks_report",
  "deployment_log",
  "access_event",
  "trivy_report",
  "fixed_log",
] as const;

export type ExpectedEvidenceCategory = (typeof EXPECTED_EVIDENCE_CATEGORIES)[number];

export function normalizeEvidenceCategory(evidenceType: string): string {
  const lower = evidenceType.toLowerCase().trim();
  if (lower === "fixed_scan") return "fixed_log";
  return lower;
}

export interface EvidenceCompletenessResult {
  linkedCount: number;
  availableTypes: string[];
  missingTypes: string[];
  missingFromTrace: string[];
  completenessPercent: number;
  confidenceImpact: "high" | "medium" | "low";
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort();
}

export function computeEvidenceCompleteness(
  evidenceFiles: EvidenceFile[],
  missingFromTrace: string[] | undefined,
): EvidenceCompletenessResult {
  const availableSet = new Set<string>();
  for (const file of evidenceFiles) {
    availableSet.add(normalizeEvidenceCategory(file.evidence_type));
  }

  const availableTypes = uniqueSorted(
    EXPECTED_EVIDENCE_CATEGORIES.filter((cat) => availableSet.has(cat)),
  );

  const missingTypes = EXPECTED_EVIDENCE_CATEGORIES.filter(
    (cat) => !availableSet.has(cat),
  );

  const traceMissing = (missingFromTrace ?? [])
    .map((item) => normalizeEvidenceCategory(item))
    .filter((item) => item.length > 0);

  const completenessPercent = Math.round(
    (availableTypes.length / EXPECTED_EVIDENCE_CATEGORIES.length) * 100,
  );

  let confidenceImpact: "high" | "medium" | "low" = "low";
  if (completenessPercent >= 85 && missingTypes.length <= 1) {
    confidenceImpact = "high";
  } else if (completenessPercent >= 60) {
    confidenceImpact = "medium";
  }

  return {
    linkedCount: evidenceFiles.length,
    availableTypes,
    missingTypes,
    missingFromTrace: uniqueSorted(traceMissing),
    completenessPercent,
    confidenceImpact,
  };
}
