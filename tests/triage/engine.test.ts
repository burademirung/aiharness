import { describe, it, expect } from "vitest";
import { triageFindings } from "../../src/triage/engine";
import type { Finding } from "../../src/types";
import type { ModelAdapter } from "../../src/adapters/model-adapter";

const finding: Finding = {
  id: "f1", ruleId: "r", cwe: "CWE-78", severity: "high", message: "m",
  file: "app.py", startLine: 1, endLine: 1, snippet: "subprocess.call(cmd, shell=True)",
};

const fakeAdapter: ModelAdapter = {
  id: "fake",
  capabilities: { maxContextTokens: 1000, supportsStructuredOutput: true, supportsSeed: false },
  analyze: async () => ({ verdict: "confirmed", severity: "high", explanation: "ok", remediation: "fix it" }),
};

describe("triageFindings", () => {
  it("enriches findings with verdict, confidence and explanation", async () => {
    const [out] = await triageFindings([finding], fakeAdapter, (f) => f.snippet);
    expect(out!.verdict).toBe("confirmed");
    expect(out!.confidence).toBe("high");
    expect(out!.explanation).toBe("ok");
    expect(out!.evidence).toContain("confirmed");
  });
  it("returns an empty array for empty findings", async () => {
    expect(await triageFindings([], fakeAdapter, (f) => f.snippet)).toEqual([]);
  });
});
