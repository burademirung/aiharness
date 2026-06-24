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

  it("clamps a missing/zero line to startLine 1 (SARIF region minimum is 1)", () => {
    const findings = normalizeSemgrep({
      results: [
        {
          check_id: "rule.with.no.line",
          path: "app.py",
          // no start/end → lines default to 0, which is SARIF-invalid
          extra: { severity: "ERROR", message: "no location" },
        },
        {
          check_id: "rule.with.zero.line",
          path: "app.py",
          start: { line: 0 },
          end: { line: 0 },
          extra: { severity: "WARNING", message: "explicit zero" },
        },
      ],
    });
    expect(findings).toHaveLength(2);
    expect(findings[0]!.startLine).toBe(1);
    expect(findings[0]!.endLine).toBe(1);
    expect(findings[1]!.startLine).toBe(1);
    expect(findings[1]!.endLine).toBe(1);
  });
});
