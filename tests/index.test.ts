import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

describe("worker entry", () => {
  it("responds to GET /api/health with ok", async () => {
    const res = await SELF.fetch("https://example.com/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });
});
