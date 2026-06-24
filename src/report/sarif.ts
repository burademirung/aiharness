import type { Finding, Severity } from "../types";

function level(sev: Severity): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium" || sev === "low") return "warning";
  return "note";
}

export function buildSarif(findings: Finding[], meta: { toolVersion: string }): object {
  const cweIds = [...new Set(findings.map((f) => f.cwe).filter((c): c is string => !!c))];
  return {
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AIHarness",
            informationUri: "https://aiharness.example",
            version: meta.toolVersion,
            rules: [...new Set(findings.map((f) => f.ruleId))].map((id) => ({ id })),
          },
        },
        taxonomies: [
          {
            name: "CWE",
            guid: "25F72D7E-8A92-459D-AD67-64853F788765",
            organization: "MITRE",
            shortDescription: { text: "The MITRE Common Weakness Enumeration" },
            taxa: cweIds.map((id) => ({ id })),
          },
        ],
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: level(f.severity),
          message: { text: f.explanation ?? f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.startLine, endLine: f.endLine, snippet: { text: f.snippet } },
              },
            },
          ],
          partialFingerprints: { primaryLocationLineHash: `${f.file}:${f.startLine}:${f.ruleId}` },
          taxa: f.cwe ? [{ toolComponent: { guid: "25F72D7E-8A92-459D-AD67-64853F788765", name: "CWE" }, id: f.cwe }] : [],
          properties: {
            confidence: f.confidence,
            verdict: f.verdict,
            evidence: f.evidence,
            remediation: f.remediation,
            cwe: f.cwe,
          },
        })),
      },
    ],
  };
}
