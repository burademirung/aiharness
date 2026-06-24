import type { Finding } from "../types";
import type { ModelAdapter } from "../adapters/model-adapter";
import { computeConfidence } from "./confidence";

export async function triageFindings(
  findings: Finding[],
  adapter: ModelAdapter,
  getWindow: (f: Finding) => string
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const f of findings) {
    const triage = await adapter.analyze({ finding: f, codeWindow: getWindow(f), cwe: f.cwe });
    // All Semgrep findings are tool-originated (deterministic = true).
    // Set false only for model-generated findings with no static-analysis backing.
    const { confidence, evidence } = computeConfidence({ deterministic: true, verdict: triage.verdict });
    out.push({
      ...f,
      verdict: triage.verdict,
      severity: triage.severity,
      confidence,
      evidence,
      explanation: triage.explanation,
      remediation: triage.remediation,
    });
  }
  return out;
}
