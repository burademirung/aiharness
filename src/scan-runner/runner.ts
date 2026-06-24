import { DurableObject } from "cloudflare:workers";
import type { Env } from "../index";
import type { Finding } from "../types";
import type { ModelAdapter } from "../adapters/model-adapter";
import { ClaudeAdapter } from "../adapters/claude";
import { normalizeSemgrep } from "./semgrep-normalize";

// ScanRunner intentionally uses the low-level `this.ctx.container` API (not the
// @cloudflare/containers Container base class) so the same class works under vitest
// (where `ctx.container` is undefined and tests override `scanFn`) and in production
// (where `ctx.container` is a real container runtime). The constructor boots the
// container when present; `scanFn` retries until the container is ready.

export class ScanRunner extends DurableObject<Env> {
  defaultPort = 8080;
  sleepAfter = "2m";

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const container = (this.ctx as any).container;
    if (container) {
      // enableInternet so Semgrep can fetch its registry ruleset (p/default).
      this.ctx.blockConcurrencyWhile(async () => { container.start({ enableInternet: true }); });
    }
  }

  // Production implementation calls the Semgrep container via the low-level port API.
  // Tests override this property before calling scanToFindings.
  scanFn = async (
    files: { path: string; content: string }[],
    language: string,
  ): Promise<unknown> => {
    const container = (this.ctx as any).container;
    if (!container) throw new Error("container runtime unavailable");
    if (!container.running) container.start({ enableInternet: true });
    const port = container.getTcpPort(8080);
    const init = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ language, files }),
    };
    // Retry ONLY while the container is still booting (connection-level errors).
    // Once we get any HTTP response the scan has run — return 2xx, fail on non-2xx
    // (do not re-run the expensive scan, which would loop for minutes).
    let lastErr: unknown;
    for (let attempt = 0; attempt < 40; attempt++) {
      try {
        const res = await port.fetch("http://container/scan", { ...init, signal: AbortSignal.timeout(150000) });
        if (res.ok) return await res.json();
        throw new Error("container scan failed: HTTP " + res.status);
      } catch (e) {
        if (e instanceof Error && e.message.startsWith("container scan failed")) throw e;
        lastErr = e;  // still booting — wait and retry
        await new Promise((r) => setTimeout(r, 1500));
      }
    }
    throw lastErr ?? new Error("container scan failed to become ready");
  };

  // overridable in tests — model adapter factory
  makeAdapter: (apiKey: string) => ModelAdapter = (apiKey) => new ClaudeAdapter(apiKey);

  async scanToFindings(
    language: string,
    files: { path: string; content: string }[],
  ): Promise<Finding[]> {
    const raw = await this.scanFn(files, language);
    return normalizeSemgrep(raw);
  }

  async runScan(scanId: string): Promise<void> {
    const { getScan, setScanStatus, setScanSarifKey, insertFindings, getJobKey, deleteJobKey, getPrJob } = await import("../db/queries");
    const { decryptKey } = await import("../crypto/envelope");
    const { triageFindings } = await import("../triage/engine");
    const { buildSarif } = await import("../report/sarif");
    const { recordAudit, hashPrompt } = await import("../report/audit");
    const { SYSTEM_PROMPT } = await import("../adapters/model-adapter");

    const env = this.env;
    // `processed` flips to true only once we commit to processing this scan (i.e. the
    // idempotency guard passed). It gates the status/source cleanup in `finally` so an
    // idempotent no-op retry of an already-finished scan does NOT flip its status or
    // re-delete its source. The job-key shred, however, ALWAYS runs (it is idempotent).
    let processed = false;
    let succeeded = false;
    let errorReason: string | null = null;
    try {
      // Load + idempotency guard INSIDE the try so that if getScan throws, the finally
      // still runs and shreds the key. A retry of an already-finished scan must be a
      // true no-op (processed stays false → no status flip, no source re-delete).
      const scan = await getScan(env.DB, scanId);
      if (!scan) return;                                 // unknown scan — nothing to do
      if (scan.status === "completed" || scan.status === "failed") return;
      processed = true;                                  // committed to processing

      await setScanStatus(env.DB, scanId, "scanning");

      // Fix 2: guard missing R2 object before parsing
      const obj = await env.SOURCE.get(scan.sourceKey);
      if (!obj) throw new Error(`source object not found: ${scan.sourceKey}`);
      const { language, files } = JSON.parse(await obj.text());

      const findings = await this.scanToFindings(language, files);

      // Build code context from the ACTUAL source, not Semgrep's `lines` field —
      // community (unauthenticated) Semgrep redacts matched lines to "requires login".
      const fileMap = new Map<string, string>(
        (files as { path: string; content: string }[]).map((x) => [x.path, x.content]),
      );
      const sliceLines = (file: string, from: number, to: number): string => {
        const content = fileMap.get(file);
        if (!content) return "";
        const lines = content.split("\n");
        return lines.slice(Math.max(0, from - 1), Math.min(lines.length, to)).join("\n");
      };
      for (const f of findings) {
        const real = sliceLines(f.file, f.startLine, f.endLine);
        if (real) f.snippet = real;                        // replace redacted snippet
      }
      const getWindow = (f: Finding): string => {
        const win = sliceLines(f.file, f.startLine - 5, f.endLine + 5);
        return win || f.snippet || "";                     // ±5 lines of real context
      };

      await setScanStatus(env.DB, scanId, "triaging");
      // Fix 2: guard missing job key before decrypting
      const envelope = await getJobKey(env.DB, scanId);
      if (!envelope) throw new Error("job key not found for scan " + scanId);
      const apiKey = await decryptKey(env.KEK, envelope);
      const adapter = this.makeAdapter(apiKey);
      const triaged = await triageFindings(findings, adapter, getWindow);

      await insertFindings(env.DB, scanId, triaged);
      const sarif = buildSarif(triaged, { toolVersion: "0.0.1" });
      const sarifKey = `sarif/${scanId}.json`;
      await env.SOURCE.put(sarifKey, JSON.stringify(sarif));
      await setScanSarifKey(env.DB, scanId, sarifKey);

      await recordAudit(env.DB, scanId, {
        modelId: "claude", modelVersion: scan.modelVersion,
        promptHash: await hashPrompt(SYSTEM_PROMPT), rulesetVersion: "p/default",
      });
      succeeded = true;

      // If this scan originated from a PR webhook, post findings back to the PR.
      // Guarded so a posting failure does NOT fail the scan (log + continue).
      try {
        const prJob = await getPrJob(env.DB, scanId);
        if (prJob) {
          const { postPrComment } = await import("../integrations/github-pr");
          await postPrComment(env, prJob, triaged);
        }
      } catch (postErr) {
        console.error("postPrComment failed for", scanId, postErr);
      }
    } catch (err) {
      // Error is recorded via succeeded=false; do not re-throw so the finally
      // cleanup always runs and callers (queue handler) see a resolved promise.
      console.error("runScan error for", scanId, err);
      // Persist a SHORT, sanitized reason (never the raw stack / API key) so
      // GET /api/scans/:id can tell the user why it failed. Cap the length.
      const raw = err instanceof Error ? err.message : "scan failed";
      errorReason = raw.replace(/\s+/g, " ").trim().slice(0, 200);
    } finally {
      // ALWAYS shred the key — idempotent (safe on a no-op retry where the key is
      // already gone). This runs even if getScan threw before `processed` was set.
      await deleteJobKey(env.DB, scanId).catch(() => {});
      // Status flip + source delete only when we actually committed to processing,
      // so an idempotent no-op retry does NOT flip a completed scan's status.
      if (processed) {
        await setScanStatus(env.DB, scanId, succeeded ? "completed" : "failed", errorReason);
        await env.SOURCE.delete(`source/${scanId}.json`).catch(() => {});  // TTL: drop source
      }
    }
  }
}
