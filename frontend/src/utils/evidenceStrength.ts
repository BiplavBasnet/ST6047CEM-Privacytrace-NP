/**
 * Display-level evidence strength derived from the diversity of evidence
 * sources attached to an incident. This mirrors the backend causality
 * engine's principle that confidence is capped when evidence is missing:
 * symptom evidence alone (live alerts / API / SIEM logs) can never produce
 * more than "weak" strength, no matter how many events there are.
 */

export type EvidenceStrengthLevel = "weak" | "medium" | "strong" | "very strong";

export interface EvidenceStrengthResult {
  level: EvidenceStrengthLevel;
  presentCategories: string[];
  missing: string[];
  summary: string;
}

/** Symptom/timeline evidence: shows the exposure happened, not why. */
const SYMPTOM_TYPES = new Set([
  "api_log",
  "runtime_log",
  "access_event",
  "siem_alert",
]);

/** Technical supporting evidence: points toward the change that likely caused it. */
const TECHNICAL_TYPES = new Set([
  "deployment_log",
  "semgrep_report",
  "gitleaks_report",
  "trivy_report",
  "scanner_bridge_import",
]);

/** Retest evidence: supports fix verification. */
const RETEST_TYPES = new Set(["fixed_log", "fixed_scan"]);

export function computeEvidenceStrength(
  evidenceTypes: string[],
  options?: { hasLiveAlert?: boolean; hasFixVerification?: boolean },
): EvidenceStrengthResult {
  const types = new Set(evidenceTypes.map((t) => (t || "").toLowerCase()));
  const hasSymptom =
    !!options?.hasLiveAlert || [...types].some((t) => SYMPTOM_TYPES.has(t));
  const hasTechnical = [...types].some((t) => TECHNICAL_TYPES.has(t));
  const hasRetest =
    !!options?.hasFixVerification || [...types].some((t) => RETEST_TYPES.has(t));

  const presentCategories: string[] = [];
  if (options?.hasLiveAlert) presentCategories.push("live privacy alerts");
  if ([...types].some((t) => SYMPTOM_TYPES.has(t)))
    presentCategories.push("API/SIEM log evidence");
  if (hasTechnical) presentCategories.push("CI/CD, deployment or scanner evidence");
  if (hasRetest) presentCategories.push("retest evidence");

  const missing: string[] = [];
  if (!hasSymptom) missing.push("API/SIEM log or live alert evidence");
  if (!hasTechnical)
    missing.push("CI/CD deployment, code/config or scanner evidence");
  if (!hasRetest) missing.push("retest evidence after the fix");

  let level: EvidenceStrengthLevel = "weak";
  if (hasSymptom && hasTechnical && hasRetest) level = "very strong";
  else if (hasSymptom && hasTechnical) level = "strong";
  else if (hasTechnical) level = "medium";
  else level = "weak";

  const summary =
    level === "very strong"
      ? "Evidence strength is very strong: symptom, technical and retest evidence are all present. Human review is still required."
      : level === "strong"
        ? "Evidence strength is strong: symptom and technical supporting evidence are present. Retest evidence would support fix verification."
        : level === "medium"
          ? "Evidence strength is medium: technical supporting evidence is present, but symptom/timeline evidence and retest evidence are still needed."
          : "Evidence strength is weak: symptom evidence alone cannot support a high-confidence likely cause. Add CI/CD, deployment or scanner evidence.";

  return { level, presentCategories, missing, summary };
}
