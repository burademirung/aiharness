import type { Finding, PrJob, ScanJob, ScanStatus } from "../types";

export async function createScan(db: D1Database, s: ScanJob): Promise<void> {
  await db
    .prepare(
      "INSERT INTO scans (id, status, language, created_at, source_key, model_id, model_version) VALUES (?,?,?,?,?,?,?)"
    )
    .bind(s.id, s.status, s.language, Date.now(), s.sourceKey, s.modelId, s.modelVersion)
    .run();
}

export async function getScan(db: D1Database, id: string): Promise<ScanJob | null> {
  const row = await db.prepare("SELECT * FROM scans WHERE id = ?").bind(id).first();
  if (!row) return null;
  return {
    id: row.id as string,
    language: row.language as string,
    status: row.status as ScanStatus,
    sourceKey: row.source_key as string,
    modelId: row.model_id as string,
    modelVersion: row.model_version as string,
  };
}

export async function setScanStatus(db: D1Database, id: string, status: ScanStatus): Promise<void> {
  const completedAt = status === "completed" || status === "failed" ? Date.now() : null;
  await db.prepare("UPDATE scans SET status = ?, completed_at = ? WHERE id = ?").bind(status, completedAt, id).run();
}

export async function setScanSarifKey(db: D1Database, id: string, sarifKey: string): Promise<void> {
  await db.prepare("UPDATE scans SET sarif_key = ? WHERE id = ?").bind(sarifKey, id).run();
}

export async function insertFindings(db: D1Database, scanId: string, findings: Finding[]): Promise<void> {
  for (const f of findings) {
    await db
      .prepare(
        "INSERT INTO findings (id, scan_id, rule_id, cwe, severity, confidence, evidence, verdict, message, file, start_line, end_line, snippet, explanation, remediation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      )
      .bind(f.id, scanId, f.ruleId, f.cwe, f.severity, f.confidence ?? null, f.evidence ?? null, f.verdict ?? null, f.message, f.file, f.startLine, f.endLine, f.snippet, f.explanation ?? null, f.remediation ?? null)
      .run();
  }
}

export async function getFindings(db: D1Database, scanId: string): Promise<Finding[]> {
  const { results } = await db.prepare("SELECT * FROM findings WHERE scan_id = ?").bind(scanId).all();
  return results.map((r: any) => ({
    id: r.id, ruleId: r.rule_id, cwe: r.cwe, severity: r.severity, message: r.message,
    file: r.file, startLine: r.start_line, endLine: r.end_line, snippet: r.snippet ?? "",
    verdict: r.verdict ?? undefined, confidence: r.confidence ?? undefined, evidence: r.evidence ?? undefined,
    explanation: r.explanation ?? undefined, remediation: r.remediation ?? undefined,
  }));
}

export async function storeJobKey(db: D1Database, scanId: string, ciphertext: string): Promise<void> {
  await db.prepare("INSERT OR REPLACE INTO job_keys (scan_id, key_ciphertext, created_at) VALUES (?,?,?)").bind(scanId, ciphertext, Date.now()).run();
}

export async function getJobKey(db: D1Database, scanId: string): Promise<string | null> {
  const row = await db.prepare("SELECT key_ciphertext FROM job_keys WHERE scan_id = ?").bind(scanId).first();
  return row ? (row.key_ciphertext as string) : null;
}

export async function deleteJobKey(db: D1Database, scanId: string): Promise<void> {
  await db.prepare("DELETE FROM job_keys WHERE scan_id = ?").bind(scanId).run();
}

export async function storePrJob(db: D1Database, job: PrJob): Promise<void> {
  await db
    .prepare(
      "INSERT OR REPLACE INTO pr_jobs (scan_id, owner, repo, pr_number, head_sha) VALUES (?,?,?,?,?)"
    )
    .bind(job.scanId, job.owner, job.repo, job.prNumber, job.headSha)
    .run();
}

export async function getPrJob(db: D1Database, scanId: string): Promise<PrJob | null> {
  const row = await db.prepare("SELECT * FROM pr_jobs WHERE scan_id = ?").bind(scanId).first();
  if (!row) return null;
  return {
    scanId: row.scan_id as string,
    owner: row.owner as string,
    repo: row.repo as string,
    prNumber: row.pr_number as number,
    headSha: row.head_sha as string,
  };
}

export async function appendAudit(db: D1Database, scanId: string, event: string, detail: unknown): Promise<void> {
  await db
    .prepare("INSERT INTO audit_log (id, scan_id, event, detail_json, at) VALUES (?,?,?,?,?)")
    .bind(crypto.randomUUID(), scanId, event, JSON.stringify(detail ?? null), Date.now())
    .run();
}
