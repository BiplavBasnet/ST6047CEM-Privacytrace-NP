import { describe, expect, it } from "vitest";
import { sanitizeString } from "../utils/safety";

describe("scanner UI safety copy", () => {
  it("blocks raw JWT-like strings in displayed text", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(sanitizeString(jwt)).toBe("[blocked sensitive value]");
  });

  it("preserves scanner bridge labels", () => {
    expect(sanitizeString("ScannerBridge-NP")).toBe("ScannerBridge-NP");
    expect(sanitizeString("supporting evidence only")).toBe("supporting evidence only");
  });
});
