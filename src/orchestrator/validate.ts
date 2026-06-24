import { ScanRequestSchema, type ScanRequest } from "../schema";

const MAX_FILES = 50;
const MAX_TOTAL_BYTES = 256 * 1024;

export type ValidationResult =
  | { ok: true; value: ScanRequest }
  | { ok: false; status: number; message: string };

export function validateScanRequest(body: unknown): ValidationResult {
  const parsed = ScanRequestSchema.safeParse(body);
  if (!parsed.success) {
    return { ok: false, status: 400, message: parsed.error.issues[0]?.message ?? "invalid request" };
  }
  const req = parsed.data;

  // Must have at least one of: files (non-empty) or repoUrl
  const hasFiles = Array.isArray(req.files) && req.files.length > 0;
  const hasRepoUrl = typeof req.repoUrl === "string" && req.repoUrl.length > 0;

  if (!hasFiles && !hasRepoUrl) {
    return { ok: false, status: 400, message: "provide files or a repoUrl" };
  }

  // Apply file caps only when files are present
  if (hasFiles && req.files) {
    if (req.files.length > MAX_FILES) {
      return { ok: false, status: 413, message: `too many files (max ${MAX_FILES})` };
    }
    const total = req.files.reduce((n, f) => n + new TextEncoder().encode(f.content).length, 0);
    if (total > MAX_TOTAL_BYTES) {
      return { ok: false, status: 413, message: `payload too large (max ${MAX_TOTAL_BYTES} bytes)` };
    }
  }

  return { ok: true, value: req };
}
