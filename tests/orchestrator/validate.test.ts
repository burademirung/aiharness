import { describe, it, expect } from "vitest";
import { validateScanRequest } from "../../src/orchestrator/validate";

const file = (content: string) => ({ path: "a.py", content });

describe("validateScanRequest", () => {
  it("accepts a valid request", () => {
    const r = validateScanRequest({ language: "python", files: [file("print(1)")], apiKey: "sk-ant-x" });
    expect(r.ok).toBe(true);
  });

  it("rejects > 50 files", () => {
    const files = Array.from({ length: 51 }, () => file("x"));
    const r = validateScanRequest({ language: "python", files, apiKey: "sk-ant-x" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(413);
  });

  it("rejects > 256 KB total", () => {
    const big = "x".repeat(257 * 1024);
    const r = validateScanRequest({ language: "python", files: [file(big)], apiKey: "sk-ant-x" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(413);
  });

  it("accepts a request with no api key (server falls back to the demo key)", () => {
    const r = validateScanRequest({ language: "python", files: [file("print(1)")] });
    expect(r.ok).toBe(true);
  });

  it("rejects a request missing files", () => {
    const r = validateScanRequest({ language: "python", files: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(400);
  });

  // repoUrl support
  it("accepts a request with only repoUrl (no files)", () => {
    const r = validateScanRequest({ language: "python", repoUrl: "https://github.com/owner/repo" });
    expect(r.ok).toBe(true);
  });

  it("rejects a request with neither files nor repoUrl", () => {
    const r = validateScanRequest({ language: "python" });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(400);
      expect(r.message).toMatch(/provide files or a repoUrl/i);
    }
  });

  it("accepts a request with both files and repoUrl (files take precedence)", () => {
    const r = validateScanRequest({
      language: "python",
      files: [file("print(1)")],
      repoUrl: "https://github.com/owner/repo",
    });
    expect(r.ok).toBe(true);
  });
});
