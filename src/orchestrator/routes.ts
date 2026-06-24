import { Hono } from "hono";
import type { Env } from "../index";
import { validateScanRequest } from "./validate";
import { encryptKey } from "../crypto/envelope";
import { createScan, getScan, getFindings, storeJobKey } from "../db/queries";
import { CLAUDE_MODEL } from "../adapters/claude";
import { fetchRepoFiles } from "../input-adapters/git-url";
import { webhook } from "./webhook";

export const api = new Hono<{ Bindings: Env }>();

// GitHub PR webhook: POST /api/webhook/github
api.route("/webhook", webhook);

api.post("/scans", async (c) => {
  const body = await c.req.json().catch(() => null);
  const v = validateScanRequest(body);
  if (!v.ok) return c.json({ error: v.message }, v.status as 400 | 413);

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
      const fetched = await fetchRepoFiles(v.value.repoUrl);
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
  await c.env.SCAN_QUEUE.send({ scanId: id });
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

api.get("/scans/:id/stream", async (c) => {
  const stub = c.env.SCAN_RUNNER.get(c.env.SCAN_RUNNER.idFromName(c.req.param("id")));
  return stub.fetch(new Request("http://do/stream"));
});
