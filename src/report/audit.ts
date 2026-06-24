import { appendAudit } from "../db/queries";

export async function recordAudit(
  db: D1Database,
  scanId: string,
  meta: { modelId: string; modelVersion: string; promptHash: string; rulesetVersion: string }
): Promise<void> {
  await appendAudit(db, scanId, "scan.completed", meta);
}

export async function hashPrompt(prompt: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(prompt));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
