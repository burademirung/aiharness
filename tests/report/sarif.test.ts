import { describe, it, expect } from "vitest";
import { buildSarif } from "../../src/report/sarif";
import type { Finding } from "../../src/types";

const finding: Finding = {
  id: "f1", ruleId: "python.command-injection", cwe: "CWE-78", severity: "high",
  message: "OS command injection", file: "app.py", startLine: 12, endLine: 12,
  snippet: "subprocess.call(cmd, shell=True)", verdict: "confirmed", confidence: "high",
  evidence: "x", explanation: "y", remediation: "z",
};

describe("buildSarif", () => {
  it("emits a valid SARIF 2.1.0 skeleton with a CWE taxonomy and one result", () => {
    const log = buildSarif([finding], { toolVersion: "0.0.1" }) as any;
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif-schema-2.1.0");
    const run = log.runs[0];
    expect(run.tool.driver.name).toBe("AIHarness");
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe("python.command-injection");
    expect(run.results[0].level).toBe("error");
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("app.py");
    expect(run.results[0].properties.confidence).toBe("high");
    expect(run.taxonomies[0].name).toBe("CWE");
    expect(run.taxonomies[0].taxa.some((t: any) => t.id === "CWE-78")).toBe(true);
    expect(run.results[0].partialFingerprints.primaryLocationLineHash).toBe("app.py:12:python.command-injection");
    expect(run.results[0].taxa[0].id).toBe("CWE-78");
  });
});
