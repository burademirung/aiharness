import { describe, it, expect } from "vitest";
import { isSeverity, SEVERITIES } from "../src/types";

describe("types", () => {
  it("recognises valid severities", () => {
    expect(SEVERITIES).toContain("high");
    expect(isSeverity("high")).toBe(true);
    expect(isSeverity("nope")).toBe(false);
  });
});
