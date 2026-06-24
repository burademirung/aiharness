/**
 * Lightweight fixed-window rate limiter for the demo `POST /api/scans` endpoint.
 *
 * Bounds the cost / DoS surface of the server-side demo key by capping:
 *   - per-IP: 20 scans / IP / hour (keyed by CF-Connecting-IP)
 *   - global: 300 scans / hour total (bounds aggregate demo-key spend)
 *
 * Backed by KV with a TTL equal to the window so counters self-expire. If the
 * KV namespace is undefined (tests / local dev), limiting is skipped (allow all).
 *
 * Webhooks (/api/webhook/github) are NOT rate-limited here — they have their own
 * HMAC signature auth.
 */

export const WINDOW_SECONDS = 60 * 60; // 1 hour
export const PER_IP_LIMIT = 20;
export const GLOBAL_LIMIT = 300;

// Minimal structural type so this module is testable with a fake KV and does not
// depend on the full @cloudflare/workers-types KVNamespace surface.
export interface RateLimitKV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface RateLimitResult {
  allowed: boolean;
  /** Which limit was hit, when blocked. Useful for logging/tests. */
  scope?: "ip" | "global";
}

/**
 * Increment the per-IP and global counters for the current fixed window and
 * return whether the request is allowed. A no-op (allowed) when `kv` is absent.
 *
 * @param kv     KV namespace, or undefined to skip limiting.
 * @param ip     Client IP (CF-Connecting-IP); empty/unknown is bucketed as "unknown".
 * @param nowMs  Current time in ms (injectable for tests).
 */
export async function checkRateLimit(
  kv: RateLimitKV | undefined,
  ip: string,
  nowMs: number = Date.now()
): Promise<RateLimitResult> {
  if (!kv) return { allowed: true }; // tests / local — no KV bound

  const windowIndex = Math.floor(nowMs / 1000 / WINDOW_SECONDS);
  const ipKey = `rl:ip:${ip || "unknown"}:${windowIndex}`;
  const globalKey = `rl:global:${windowIndex}`;

  const [ipRaw, globalRaw] = await Promise.all([kv.get(ipKey), kv.get(globalKey)]);
  const ipCount = Number(ipRaw ?? 0);
  const globalCount = Number(globalRaw ?? 0);

  if (ipCount >= PER_IP_LIMIT) return { allowed: false, scope: "ip" };
  if (globalCount >= GLOBAL_LIMIT) return { allowed: false, scope: "global" };

  // Count this request. TTL keeps a little past the window so the counter expires.
  await Promise.all([
    kv.put(ipKey, String(ipCount + 1), { expirationTtl: WINDOW_SECONDS + 60 }),
    kv.put(globalKey, String(globalCount + 1), { expirationTtl: WINDOW_SECONDS + 60 }),
  ]);

  return { allowed: true };
}
