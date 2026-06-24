import { Hono } from "hono";
import type { Env } from "../index";
import { validateScanRequest } from "./validate";
import { encryptKey } from "../crypto/envelope";
import { createScan, getScan, getFindings, storeJobKey, deleteJobKey } from "../db/queries";
import { CLAUDE_MODEL } from "../adapters/claude";
import { fetchRepoFiles } from "../input-adapters/git-url";
import { webhook } from "./webhook";
import { checkRateLimit } from "./ratelimit";

export const api = new Hono<{ Bindings: Env }>();

// GitHub PR webhook: POST /api/webhook/github
api.route("/webhook", webhook);

api.post("/scans", async (c) => {
  const body = await c.req.json().catch(() => null);
  const v = validateScanRequest(body);
  if (!v.ok) return c.json({ error: v.message }, v.status as 400 | 413);

  // Demo rate limit (no-op when RATE_LIMIT KV is unbound, e.g. tests/local).
  const ip = c.req.header("cf-connecting-ip") ?? "";
  const rl = await checkRateLimit(c.env.RATE_LIMIT, ip);
  if (!rl.allowed) return c.json({ error: "rate limit exceeded — try again later" }, 429);

  // BYO key if provided; otherwise fall back to the server's demo key so visitors
  // can try the live scan without bringing their own key.
  const apiKey = (v.value.apiKey && v.value.apiKey.trim()) || c.env.DEMO_ANTHROPIC_KEY;
  if (!apiKey) return c.json({ error: "no API key provided and no demo key configured" }, 400);

  // Resolve language + files: either from the request body or by fetching a GitHub repo.
  let language = v.value.language;
  let files = v.value.files;

  const hasFiles = Array.isArray(files) && files.length > 0;
  if (!hasFiles && v.value.repoUrl) {
    try {
      // Pass the optional server GITHUB_TOKEN to raise the GitHub REST rate
      // limit (60/h unauth → 5000/h). No-op when unset.
      const fetched = await fetchRepoFiles(v.value.repoUrl, { token: c.env.GITHUB_TOKEN });
      language = fetched.language;
      files = fetched.files;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "failed to fetch repository";
      return c.json({ error: msg }, 400);
    }
  }

  const id = crypto.randomUUID();
  const sourceKey = `source/${id}.json`;
  await c.env.SOURCE.put(sourceKey, JSON.stringify({ language, files }));
  await createScan(c.env.DB, {
    id, language, status: "queued", sourceKey,
    modelId: "claude", modelVersion: CLAUDE_MODEL,
  });
  const envelope = await encryptKey(c.env.KEK, apiKey);
  await storeJobKey(c.env.DB, id, envelope);
  // If enqueue fails AFTER the job key was stored, the ciphertext would be orphaned
  // (no worker will ever shred it). Delete it and surface a clear 500.
  try {
    await c.env.SCAN_QUEUE.send({ scanId: id });
  } catch {
    await deleteJobKey(c.env.DB, id).catch(() => {});
    return c.json({ error: "failed to enqueue scan" }, 500);
  }
  return c.json({ id }, 202);
});

api.get("/scans/:id", async (c) => {
  const scan = await getScan(c.env.DB, c.req.param("id"));
  if (!scan) return c.json({ error: "not found" }, 404);
  const findings = await getFindings(c.env.DB, scan.id);
  return c.json({ scan, findings });
});

api.get("/scans/:id/sarif", async (c) => {
  const id = c.req.param("id");
  const obj = await c.env.SOURCE.get(`sarif/${id}.json`);
  if (!obj) return c.json({ error: "not ready" }, 404);
  return new Response(obj.body, { headers: { "content-type": "application/json", "content-disposition": `attachment; filename="${id}.sarif"` } });
});
