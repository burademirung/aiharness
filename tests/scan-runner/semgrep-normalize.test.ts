import { describe, it, expect } from "vitest";
import semgrep from "../../fixtures/semgrep-output.json";
import { normalizeSemgrep } from "../../src/scan-runner/semgrep-normalize";

describe("normalizeSemgrep", () => {
  it("maps a result to a Finding with CWE and severity", () => {
    const findings = normalizeSemgrep(semgrep);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("python.lang.security.audit.dangerous-subprocess-use");
    expect(f.cwe).toBe("CWE-78");
    expect(f.severity).toBe("high");
    expect(f.file).toBe("app.py");
    expect(f.startLine).toBe(12);
    expect(f.snippet).toContain("subprocess");
  });

  it("returns [] for empty results", () => {
    expect(normalizeSemgrep({ results: [], errors: [] })).toEqual([]);
  });
});
