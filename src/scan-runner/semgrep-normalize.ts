import type { Finding, Severity } from "../types";

function mapSeverity(s: string): Severity {
  switch (s) {
    case "ERROR": return "high";
    case "WARNING": return "medium";
    default: return "low";
  }
}

function extractCwe(meta: any): string | null {
  const cwe = meta?.cwe;
  const first = Array.isArray(cwe) ? cwe[0] : cwe;
  if (typeof first !== "string") return null;
  const m = first.match(/CWE-\d+/);
  return m ? m[0] : null;
}

export function normalizeSemgrep(json: unknown): Finding[] {
  const results = (json as any)?.results;
  if (!Array.isArray(results)) return [];
  return results.map((r: any) => ({
    id: crypto.randomUUID(),
    ruleId: String(r.check_id ?? "unknown"),
    cwe: extractCwe(r.extra?.metadata),
    severity: mapSeverity(String(r.extra?.severity ?? "INFO")),
    message: String(r.extra?.message ?? ""),
    file: String(r.path ?? ""),
    // SARIF region.startLine/endLine have a schema minimum of 1; clamp so a result
    // with a missing/zero line never produces a schema-INVALID SARIF document.
    startLine: Math.max(1, Number(r.start?.line ?? 0)),
    endLine: Math.max(1, Number(r.end?.line ?? r.start?.line ?? 0)),
    snippet: String(r.extra?.lines ?? ""),
  }));
}
