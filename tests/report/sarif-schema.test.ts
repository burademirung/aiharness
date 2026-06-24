import { describe, it, expect } from "vitest";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { readFileSync } from "fs";
import { resolve } from "path";
import { buildSarif } from "../../src/report/sarif";
import type { Finding } from "../../src/types";

// Load the SARIF 2.1.0 JSON Schema (schemastore draft-07 version)
const schemaPath = resolve(__dirname, "../fixtures/sarif-schema-2.1.0.json");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

// Representative findings: one WITH a cwe, one WITHOUT; varied severities
const findings: Finding[] = [
  {
    id: "f1",
    ruleId: "python.command-injection",
    cwe: "CWE-78",
    severity: "high",          // maps to level "error"
    message: "OS command injection detected",
    file: "app.py",
    startLine: 12,
    endLine: 12,
    snippet: "subprocess.call(cmd, shell=True)",
    verdict: "confirmed",
    confidence: "high",
    evidence: "shell=True with user input",
    explanation: "User-controlled input flows into shell command",
    remediation: "Use subprocess.run with a list and shell=False",
  },
  {
    id: "f2",
    ruleId: "python.sql-injection",
    cwe: null,          // no CWE — exercises the empty-taxa branch
    severity: "medium", // maps to level "warning"
    message: "Potential SQL injection",
    file: "db.py",
    startLine: 42,
    endLine: 42,
    snippet: 'cursor.execute("SELECT * FROM users WHERE id=" + uid)',
    verdict: "uncertain",
    confidence: "low",
    evidence: "string concatenation in query",
    explanation: "String concatenation used to build SQL query",
    remediation: "Use parameterised queries",
  },
  {
    id: "f3",
    ruleId: "python.info-disclosure",
    cwe: "CWE-200",
    severity: "info", // maps to level "note"
    message: "Sensitive data in log output",
    file: "utils.py",
    startLine: 7,
    endLine: 7,
    snippet: "logger.debug(f'password={password}')",
    verdict: "confirmed",
    confidence: "medium",
    evidence: "password logged at debug level",
    explanation: "Password written to log",
    remediation: "Remove or redact sensitive fields before logging",
  },
];

describe("buildSarif SARIF 2.1.0 schema validation", () => {
  it("produces output that satisfies the official SARIF 2.1.0 JSON Schema", () => {
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(schema);

    const doc = buildSarif(findings, { toolVersion: "0.0.1" });

    const ok = validate(doc);
    if (!ok) console.error(validate.errors);
    expect(ok).toBe(true);
  });

  it("exercises all three SARIF levels (error / warning / note)", () => {
    const doc = buildSarif(findings, { toolVersion: "0.0.1" }) as any;
    const levels = doc.runs[0].results.map((r: any) => r.level) as string[];
    expect(levels).toContain("error");
    expect(levels).toContain("warning");
    expect(levels).toContain("note");
  });

  it("omits taxa array from results that have no CWE", () => {
    const doc = buildSarif(findings, { toolVersion: "0.0.1" }) as any;
    // f2 has cwe: null — its taxa array must be empty (or absent)
    const sqlResult = doc.runs[0].results.find((r: any) => r.ruleId === "python.sql-injection");
    expect(sqlResult).toBeDefined();
    expect(sqlResult.taxa).toHaveLength(0);
  });
});
