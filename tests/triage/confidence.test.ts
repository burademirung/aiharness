import { describe, it, expect } from "vitest";
import { computeConfidence } from "../../src/triage/confidence";

describe("computeConfidence", () => {
  it("high when deterministic + LLM-confirmed", () => {
    const r = computeConfidence({ deterministic: true, verdict: "confirmed" });
    expect(r.confidence).toBe("high");
  });
  it("medium when deterministic but LLM uncertain", () => {
    const r = computeConfidence({ deterministic: true, verdict: "uncertain" });
    expect(r.confidence).toBe("medium");
  });
  it("low when LLM refutes a deterministic finding", () => {
    const r = computeConfidence({ deterministic: true, verdict: "refuted" });
    expect(r.confidence).toBe("low");
    expect(r.evidence).toContain("refuted");
  });
  it("low when model-only (no deterministic basis)", () => {
    const r = computeConfidence({ deterministic: false, verdict: "confirmed" });
    expect(r.confidence).toBe("low");
    expect(r.evidence).toContain("Model-originated");
  });
});
