import { describe, it, expect } from "vitest";
import {
  checkRateLimit,
  PER_IP_LIMIT,
  GLOBAL_LIMIT,
  type RateLimitKV,
} from "../../src/orchestrator/ratelimit";

/** Minimal in-memory fake KV (ignores TTL — tests use a fixed window). */
function fakeKV(): RateLimitKV & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    async get(key) {
      return store.get(key) ?? null;
    },
    async put(key, value) {
      store.set(key, value);
    },
  };
}

const NOW = 1_700_000_000_000; // fixed timestamp → single window

describe("checkRateLimit", () => {
  it("is a no-op (allow) when KV is undefined", async () => {
    const res = await checkRateLimit(undefined, "1.2.3.4", NOW);
    expect(res.allowed).toBe(true);
  });

  it("increments the per-IP counter and blocks past the cap", async () => {
    const kv = fakeKV();
    // First PER_IP_LIMIT requests allowed.
    for (let i = 0; i < PER_IP_LIMIT; i++) {
      const res = await checkRateLimit(kv, "1.2.3.4", NOW);
      expect(res.allowed).toBe(true);
    }
    // The next one is blocked with scope "ip".
    const blocked = await checkRateLimit(kv, "1.2.3.4", NOW);
    expect(blocked.allowed).toBe(false);
    expect(blocked.scope).toBe("ip");
  });

  it("keeps separate counters per IP", async () => {
    const kv = fakeKV();
    for (let i = 0; i < PER_IP_LIMIT; i++) {
      await checkRateLimit(kv, "1.1.1.1", NOW);
    }
    // A different IP still has fresh budget.
    const res = await checkRateLimit(kv, "2.2.2.2", NOW);
    expect(res.allowed).toBe(true);
  });

  it("enforces the global cap across IPs", async () => {
    const kv = fakeKV();
    // Drive the global counter to the cap using many distinct IPs so per-IP
    // limits never trigger first (GLOBAL_LIMIT < PER_IP_LIMIT * #IPs).
    let allowedCount = 0;
    for (let i = 0; i < GLOBAL_LIMIT; i++) {
      const res = await checkRateLimit(kv, `ip-${i}`, NOW);
      if (res.allowed) allowedCount++;
    }
    expect(allowedCount).toBe(GLOBAL_LIMIT);
    const blocked = await checkRateLimit(kv, "fresh-ip", NOW);
    expect(blocked.allowed).toBe(false);
    expect(blocked.scope).toBe("global");
  });
});
