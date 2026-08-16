import { describe, expect, it } from "vitest";

import { hasPermission } from "../utils/permissions";

describe("review permission split", () => {
  it("allows auditors to read reviews but not submit them", () => {
    expect(hasPermission("auditor", "incident:review_read")).toBe(true);
    expect(hasPermission("auditor", "incident:review")).toBe(false);
  });

  it("allows security analysts to read and submit reviews", () => {
    expect(hasPermission("security_analyst", "incident:review_read")).toBe(true);
    expect(hasPermission("security_analyst", "incident:review")).toBe(true);
  });
});
