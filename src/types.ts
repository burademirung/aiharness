export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export function isSeverity(x: unknown): x is Severity {
  return typeof x === "string" && (SEVERITIES as readonly string[]).includes(x);
}

export type Verdict = "confirmed" | "refuted" | "uncertain";
export type Confidence = "low" | "medium" | "high";
export type ScanStatus = "queued" | "scanning" | "triaging" | "completed" | "failed";

export interface Finding {
  id: string;
  ruleId: string;          // semgrep rule id
  cwe: string | null;      // e.g. "CWE-89"
  severity: Severity;
  message: string;
  file: string;
  startLine: number;
  endLine: number;
  snippet: string;
  // populated after triage:
  verdict?: Verdict;
  confidence?: Confidence;
  evidence?: string;       // why this confidence was assigned
  explanation?: string;
  remediation?: string;
}

export interface ScanJob {
  id: string;
  language: string;
  status: ScanStatus;
  sourceKey: string;       // R2 key
  modelId: string;
  modelVersion: string;
}

export interface PrJob {
  scanId: string;
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
}

export interface TriageInput {
  finding: Finding;
  codeWindow: string;      // surrounding context, delimited
  cwe: string | null;
}

export interface TriageOutput {
  verdict: Verdict;
  severity: Severity;
  explanation: string;
  remediation: string;
}
