import { Hono } from "hono";
import type { Env } from "../index";
import { encryptKey } from "../crypto/envelope";
import { createScan, storeJobKey, storePrJob } from "../db/queries";
import { CLAUDE_MODEL } from "../adapters/claude";

// Extensions we can scan, mapped to semgrep-ish language names. Mirrors the
// allowlist used by the git-url adapter — only these files are scanned.
const EXT_TO_LANG: Record<string, string> = {
  py: "python",
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  java: "java",
  go: "go",
  rb: "ruby",
  php: "php",
  c: "c",
  cpp: "cpp",
  cs: "csharp",
  rs: "rust",
};

const MAX_FILES = 50;
const MAX_TOTAL_BYTES = 256 * 1024;

interface PrFile {
  filename: string;
  status: string; // added | modified | removed | renamed | ...
}

/**
 * Constant-time compare of two equal-length byte arrays. Returns false for
 * length mismatch. Avoids early-exit timing leaks on the signature check.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Verify a GitHub `X-Hub-Signature-256` header against the raw body using
 * HMAC-SHA256(secret, rawBody), with a constant-time comparison.
 * Exported for direct unit testing.
 */
export async function verifySignature(
  secret: string,
  rawBody: string,
  signatureHeader: string | null | undefined
): Promise<boolean> {
  if (!signatureHeader) return false;
  const prefix = "sha256=";
  if (!signatureHeader.startsWith(prefix)) return false;
  const provided = hexToBytes(signatureHeader.slice(prefix.length));
  if (!provided) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody))
  );
  return timingSafeEqual(provided, mac);
}

/** Compute the `sha256=...` signature header value for a body. */
export async function computeSignature(secret: string, rawBody: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody))
  );
  return "sha256=" + bytesToHex(mac);
}

const ACTED_ACTIONS = new Set(["opened", "synchronize", "reopened"]);

/**
 * Fetch the PR's changed source files (within the allowlist + caps) at headSha.
 * `fetchImpl` is injectable so tests never hit the real GitHub API.
 */
export async function collectChangedFiles(opts: {
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  token: string;
  fetchImpl?: typeof fetch;
}): Promise<{ language: string; files: Array<{ path: string; content: string }> }> {
  const { owner, repo, prNumber, headSha, token } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const headers = {
    authorization: `Bearer ${token}`,
    accept: "application/vnd.github+json",
    "user-agent": "aiharness",
    "x-github-api-version": "2022-11-28",
  };

  // List changed files (paginate up to a few pages; capped by MAX_FILES anyway).
  const changed: PrFile[] = [];
  for (let page = 1; page <= 10; page++) {
    const res = await fetchImpl(
      `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100&page=${page}`,
      { headers } as RequestInit
    );
    if (!res.ok) throw new Error(`GitHub API error listing PR files: ${res.status}`);
    const batch = (await res.json()) as PrFile[];
    changed.push(...batch);
    if (batch.length < 100) break;
  }

  // Keep only scannable, non-removed source files.
  const candidates = changed.filter((f) => {
    if (f.status === "removed") return false;
    const ext = f.filename.split(".").pop()?.toLowerCase() ?? "";
    return Boolean(EXT_TO_LANG[ext]);
  });

  const files: Array<{ path: string; content: string; ext: string }> = [];
  let totalBytes = 0;
  for (const c of candidates) {
    if (files.length >= MAX_FILES) break;
    // Fetch content at the head sha via the raw media type of the contents API.
    const res = await fetchImpl(
      `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURI(c.filename)}?ref=${headSha}`,
      { headers: { ...headers, accept: "application/vnd.github.raw" } } as RequestInit
    );
    if (!res.ok) continue; // skip files we can't fetch
    const content = await res.text();
    const byteLen = new TextEncoder().encode(content).length;
    if (totalBytes + byteLen > MAX_TOTAL_BYTES) break;
    const ext = c.filename.split(".").pop()?.toLowerCase() ?? "";
    files.push({ path: c.filename, content, ext });
    totalBytes += byteLen;
  }

  if (files.length === 0) {
    throw new Error("no scannable changed source files in PR");
  }

  // Infer language from the most common extension.
  const extCount: Record<string, number> = {};
  for (const f of files) extCount[f.ext] = (extCount[f.ext] ?? 0) + 1;
  const dominantExt = Object.entries(extCount).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  const language = EXT_TO_LANG[dominantExt] ?? "python";

  return { language, files: files.map(({ path, content }) => ({ path, content })) };
}

interface PullRequestEvent {
  action?: string;
  number?: number;
  pull_request?: {
    number?: number;
    head?: { sha?: string };
  };
  repository?: {
    name?: string;
    owner?: { login?: string };
  };
}

// Injectable fetch for the outbound GitHub API calls. Tests call setWebhookFetch
// to avoid real network; production leaves it undefined and uses global fetch.
let injectedFetch: typeof fetch | undefined;
export function setWebhookFetch(f: typeof fetch | undefined): void {
  injectedFetch = f;
}

export const webhook = new Hono<{ Bindings: Env }>();

webhook.post("/github", async (c) => {
  const secret = c.env.GITHUB_WEBHOOK_SECRET;
  const token = c.env.GITHUB_TOKEN;
  if (!secret || !token) {
    return c.json({ error: "webhook not configured" }, 503);
  }

  // Read the RAW body exactly once — signature is computed over these bytes.
  const rawBody = await c.req.text();
  const ok = await verifySignature(secret, rawBody, c.req.header("x-hub-signature-256"));
  if (!ok) return c.json({ error: "invalid signature" }, 401);

  const event = c.req.header("x-github-event");
  if (event === "ping") return c.json({ ok: true }, 200);
  if (event !== "pull_request") return c.json({ ok: true, ignored: event ?? "unknown" }, 200);

  let payload: PullRequestEvent;
  try {
    payload = JSON.parse(rawBody) as PullRequestEvent;
  } catch {
    return c.json({ error: "invalid JSON" }, 400);
  }

  const action = payload.action ?? "";
  if (!ACTED_ACTIONS.has(action)) {
    return c.json({ ok: true, ignored: action }, 200);
  }

  const owner = payload.repository?.owner?.login;
  const repo = payload.repository?.name;
  const prNumber = payload.pull_request?.number ?? payload.number;
  const headSha = payload.pull_request?.head?.sha;
  if (!owner || !repo || !prNumber || !headSha) {
    return c.json({ error: "incomplete pull_request payload" }, 400);
  }

  // BYO key not available over a webhook — use the server demo key.
  const apiKey = c.env.DEMO_ANTHROPIC_KEY;
  if (!apiKey) return c.json({ error: "no demo key configured" }, 503);

  let collected;
  try {
    collected = await collectChangedFiles({
      owner, repo, prNumber, headSha, token, fetchImpl: injectedFetch,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "failed to collect PR files";
    return c.json({ error: msg }, 422);
  }

  // Enqueue a scan EXACTLY like POST /scans, then persist PR context.
  const id = crypto.randomUUID();
  const sourceKey = `source/${id}.json`;
  await c.env.SOURCE.put(sourceKey, JSON.stringify({ language: collected.language, files: collected.files }));
  await createScan(c.env.DB, {
    id, language: collected.language, status: "queued", sourceKey,
    modelId: "claude", modelVersion: CLAUDE_MODEL,
  });
  const envelope = await encryptKey(c.env.KEK, apiKey);
  await storeJobKey(c.env.DB, id, envelope);
  await storePrJob(c.env.DB, { scanId: id, owner, repo, prNumber, headSha });
  await c.env.SCAN_QUEUE.send({ scanId: id });

  return c.json({ ok: true, scanId: id }, 202);
});
