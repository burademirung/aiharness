import { Hono } from "hono";
import { api } from "./orchestrator/routes";
import { ScanRunner } from "./scan-runner/runner";

export { ScanRunner };

export interface Env {
  DB: D1Database;
  SOURCE: R2Bucket;
  SCAN_QUEUE: Queue;
  // Parameterized so RPC calls (e.g. stub.runScan) are type-checked at the call site.
  SCAN_RUNNER: DurableObjectNamespace<ScanRunner>;
  ASSETS: Fetcher;
  KEK: string;
  // Server-side demo key used when a scan request omits apiKey (BYO key optional).
  DEMO_ANTHROPIC_KEY?: string;
  // GitHub PR-webhook secrets (optional). If unset, the webhook returns 503
  // "webhook not configured". GITHUB_WEBHOOK_SECRET verifies inbound signatures;
  // GITHUB_TOKEN authenticates outbound GitHub API calls (file fetch + comment).
  GITHUB_WEBHOOK_SECRET?: string;
  GITHUB_TOKEN?: string;
}

const app = new Hono<{ Bindings: Env }>();

app.get("/api/health", (c) => c.json({ status: "ok" }));

app.route("/api", api);
app.get("*", (c) => c.env.ASSETS.fetch(c.req.raw)); // serve the UI

export default {
  fetch: app.fetch,
  async queue(batch: MessageBatch<{ scanId: string }>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      const stub = env.SCAN_RUNNER.get(env.SCAN_RUNNER.idFromName(msg.body.scanId));
      // Retries are disabled (max_retries: 0) because the BYO API key is
      // shredded in runScan's finally block after the first attempt, making
      // a retry impossible.  Always ack so a poison message is not re-queued.
      // runScan records terminal "failed" status itself.
      try {
        await stub.runScan(msg.body.scanId);
      } catch (err) {
        console.error("scan failed", msg.body.scanId, err);
      }
      msg.ack();
    }
  },
};
