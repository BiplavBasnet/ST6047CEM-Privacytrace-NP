import { describe, expect, it } from "vitest";
import { getMissingRetestDimensions, isExactRetestReady } from "../utils/controlledRemediation";

describe("controlled remediation lifecycle resume gates", () => {
  it("resumes a persisted exact current test and controlled retest", () => {
    expect(isExactRetestReady(false,
      { status: "completed", workflow_status: "current", dimensions_match: true },
      { status: "passed", workflow_status: "current" },
    )).toBe(true);
  });

  it("blocks controlled retest creation when a server dimension is missing", () => {
    expect(getMissingRetestDimensions({
      service_name: "wallet-api",
      endpoint: "/payments",
      exposure_location: null,
      component: "request_logger",
    })).toEqual(["exposure location"]);
  });
});
