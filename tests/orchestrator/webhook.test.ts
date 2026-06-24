import { describe, it, expect } from "vitest";
import { webhook, computeSignature, verifySignature } from "../../src/orchestrator/webhook";

const SECRET = "test-webhook-secret";

// Minimal env: secret + token present so the webhook is "configured", but the
// security-critical paths (ping, ignored action, signature checks) never reach
// the GitHub API, so no network/DB is touched.
const baseEnv = {
  GITHUB_WEBHOOK_SECRET: SECRET,
  GITHUB_TOKEN: "ghtok",
} as any;

async function post(body: string, headers: Record<string, string>, env = baseEnv) {
  const req = new Request("http://test/github", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
  return webhook.fetch(req, env);
}

describe("webhook signature verification", () => {
  it("verifySignature: round-trips a correctly signed body", async () => {
    const body = JSON.stringify({ hello: "world" });
    const sig = await computeSignature(SECRET, body);
    expect(sig.startsWith("sha256=")).toBe(true);
    expect(await verifySignature(SECRET, body, sig)).toBe(true);
  });

  it("verifySignature: rejects a wrong signature", async () => {
    const body = JSON.stringify({ hello: "world" });
    const sig = await computeSignature(SECRET, body);
    // flip a hex char
    const tampered = sig.slice(0, -1) + (sig.endsWith("0") ? "1" : "0");
    expect(await verifySignature(SECRET, body, tampered)).toBe(false);
  });

  it("verifySignature: rejects missing / malformed signature", async () => {
    const body = "x";
    expect(await verifySignature(SECRET, body, undefined)).toBe(false);
    expect(await verifySignature(SECRET, body, "")).toBe(false);
    expect(await verifySignature(SECRET, body, "notprefixed")).toBe(false);
    expect(await verifySignature(SECRET, body, "sha256=zzzz")).toBe(false);
  });

  it("verifySignature: rejects body signed with a different secret", async () => {
    const body = JSON.stringify({ a: 1 });
    const sig = await computeSignature("other-secret", body);
    expect(await verifySignature(SECRET, body, sig)).toBe(false);
  });
});

describe("webhook endpoint", () => {
  it("returns 503 when not configured", async () => {
    const body = JSON.stringify({});
    const res = await post(body, {}, { GITHUB_WEBHOOK_SECRET: "", GITHUB_TOKEN: "" } as any);
    expect(res.status).toBe(503);
  });

  it("accepts a correctly signed ping → 200 {ok:true}", async () => {
    const body = JSON.stringify({ zen: "Practicality beats purity." });
    const sig = await computeSignature(SECRET, body);
    const res = await post(body, { "x-github-event": "ping", "x-hub-signature-256": sig });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("rejects a wrong signature → 401", async () => {
    const body = JSON.stringify({ zen: "x" });
    const res = await post(body, {
      "x-github-event": "ping",
      "x-hub-signature-256": "sha256=" + "0".repeat(64),
    });
    expect(res.status).toBe(401);
  });

  it("rejects a missing signature → 401", async () => {
    const body = JSON.stringify({ zen: "x" });
    const res = await post(body, { "x-github-event": "ping" });
    expect(res.status).toBe(401);
  });

  it("ignores a pull_request with an unhandled action → 200 no-op", async () => {
    const body = JSON.stringify({
      action: "closed",
      pull_request: { number: 7, head: { sha: "abc" } },
      repository: { name: "repo", owner: { login: "owner" } },
    });
    const sig = await computeSignature(SECRET, body);
    const res = await post(body, {
      "x-github-event": "pull_request",
      "x-hub-signature-256": sig,
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { ok: boolean; ignored: string };
    expect(json.ok).toBe(true);
    expect(json.ignored).toBe("closed");
  });

  it("ignores a non-pull_request event → 200", async () => {
    const body = JSON.stringify({ action: "opened" });
    const sig = await computeSignature(SECRET, body);
    const res = await post(body, {
      "x-github-event": "issues",
      "x-hub-signature-256": sig,
    });
    expect(res.status).toBe(200);
  });
});
