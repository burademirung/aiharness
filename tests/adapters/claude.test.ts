import { describe, it, expect } from "vitest";
import fixture from "../../fixtures/claude-response.json";
import { ClaudeAdapter } from "../../src/adapters/claude";
import type { TriageInput } from "../../src/types";

const input: TriageInput = {
  finding: {
    id: "f1", ruleId: "r", cwe: "CWE-78", severity: "high", message: "m",
    file: "app.py", startLine: 1, endLine: 1, snippet: "subprocess.call(cmd, shell=True)",
  },
  codeWindow: "subprocess.call(cmd, shell=True)",
  cwe: "CWE-78",
};

describe("ClaudeAdapter", () => {
  it("parses a valid model response into TriageOutput", async () => {
    const adapter = new ClaudeAdapter("fake-key", async () => fixture.valid);
    const out = await adapter.analyze(input);
    expect(out.verdict).toBe("confirmed");
    expect(out.severity).toBe("high");
    expect(out.remediation).toContain("shell=True");
  });

  it("degrades to needs-review on persistently invalid output", async () => {
    const adapter = new ClaudeAdapter("fake-key", async () => fixture.garbage);
    const out = await adapter.analyze(input);
    expect(out.verdict).toBe("uncertain");
    expect(out.explanation).toContain("needs review");
  });

  it("degrades to needs-review when the model call throws (e.g. network error)", async () => {
    const adapter = new ClaudeAdapter("fake-key", async () => { throw new Error("network error"); });
    const out = await adapter.analyze(input);
    expect(out.verdict).toBe("uncertain");
    expect(out.explanation).toContain("needs review");
  });
});
