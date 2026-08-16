import { describe, expect, it } from "vitest";
import { computeEvidenceStrength } from "../utils/evidenceStrength";

describe("live-first evidence strength", () => {
  it("keeps live and uploaded symptom evidence weak", () => {
    expect(computeEvidenceStrength([], { hasLiveAlert: true }).level).toBe("weak");
    expect(
      computeEvidenceStrength(["api_log", "siem_alert"], {
        hasLiveAlert: true,
      }).level,
    ).toBe("weak");
  });

  it("requires technical evidence for strong and retest for very strong", () => {
    expect(
      computeEvidenceStrength(["api_log", "deployment_log"], {
        hasLiveAlert: true,
      }).level,
    ).toBe("strong");
    expect(
      computeEvidenceStrength(
        ["siem_alert", "semgrep_report", "fixed_log"],
        { hasLiveAlert: true },
      ).level,
    ).toBe("very strong");
  });
});
