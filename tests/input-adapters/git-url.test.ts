import { describe, it, expect } from "vitest";
import { parseGitHubUrl, fetchRepoFiles } from "../../src/input-adapters/git-url";

// ---------------------------------------------------------------------------
// parseGitHubUrl
// ---------------------------------------------------------------------------
describe("parseGitHubUrl", () => {
  it("parses a basic owner/repo URL", () => {
    const result = parseGitHubUrl("https://github.com/owner/repo");
    expect(result).toEqual({ owner: "owner", repo: "repo", ref: undefined });
  });

  it("parses a URL with a /tree/ref branch", () => {
    const result = parseGitHubUrl("https://github.com/owner/repo/tree/main");
    expect(result).toEqual({ owner: "owner", repo: "repo", ref: "main" });
  });

  it("parses a URL with a /tree/ref containing slashes (tag or branch path)", () => {
    const result = parseGitHubUrl("https://github.com/owner/repo/tree/feature/my-branch");
    expect(result).toEqual({ owner: "owner", repo: "repo", ref: "feature/my-branch" });
  });

  it("strips a trailing .git suffix", () => {
    const result = parseGitHubUrl("https://github.com/owner/repo.git");
    expect(result).toEqual({ owner: "owner", repo: "repo", ref: undefined });
  });

  it("returns null for a non-GitHub URL", () => {
    expect(parseGitHubUrl("https://gitlab.com/owner/repo")).toBeNull();
  });

  it("returns null for a malformed URL (no repo segment)", () => {
    expect(parseGitHubUrl("https://github.com/owner")).toBeNull();
  });

  it("returns null for a plain invalid URL string", () => {
    expect(parseGitHubUrl("not-a-url")).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(parseGitHubUrl("")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// fetchRepoFiles — all network is faked via fetchImpl
// ---------------------------------------------------------------------------

function makeRepoResponse(defaultBranch = "main") {
  return {
    default_branch: defaultBranch,
    name: "repo",
    full_name: "owner/repo",
  };
}

function makeTreeResponse(files: Array<{ path: string; size?: number }>) {
  return {
    tree: files.map((f) => ({
      path: f.path,
      type: "blob",
      size: f.size ?? 100,
      url: `https://api.github.com/repos/owner/repo/git/blobs/abc`,
    })),
    truncated: false,
  };
}

function makeFetchImpl(responses: Record<string, { status: number; body: unknown }>) {
  return async (url: string) => {
    // Prefer the key whose match starts latest in the URL (most-specific suffix wins).
    // e.g. "git/trees/main" wins over "repos/owner/repo" when both match the tree URL.
    const key = Object.keys(responses)
      .filter((k) => url.includes(k))
      .sort((a, b) => url.lastIndexOf(b) - url.lastIndexOf(a))[0];
    if (!key) throw new Error(`Unexpected fetch URL in test: ${url}`);
    const { status, body } = responses[key];
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    } as unknown as Response;
  };
}

describe("fetchRepoFiles", () => {
  it("collects source files from a repo using the default branch", async () => {
    const fetchImpl = makeFetchImpl({
      "api.github.com/repos/owner/repo)": { status: 200, body: makeRepoResponse("main") },
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": {
        status: 200,
        body: makeTreeResponse([
          { path: "src/app.py", size: 50 },
          { path: "src/utils.py", size: 30 },
          { path: "README.md", size: 200 },      // should be skipped (not in allowlist)
        ]),
      },
      "raw.githubusercontent.com/owner/repo/main/src/app.py": {
        status: 200,
        body: "print('hello')",
      },
      "raw.githubusercontent.com/owner/repo/main/src/utils.py": {
        status: 200,
        body: "def foo(): pass",
      },
    });

    const result = await fetchRepoFiles("https://github.com/owner/repo", { fetchImpl });
    expect(result.language).toBe("python");
    expect(result.files).toHaveLength(2);
    expect(result.files.map((f) => f.path)).toContain("src/app.py");
    expect(result.files.map((f) => f.path)).toContain("src/utils.py");
  });

  it("uses the ref from the URL instead of fetching the default branch", async () => {
    let repoCalled = false;
    const fetchImpl = async (url: string) => {
      if (url.includes("api.github.com/repos/owner/repo") && !url.includes("git/trees")) {
        repoCalled = true;
      }
      if (url.includes("api.github.com/repos/owner/repo") && url.includes("git/trees/dev")) {
        return {
          ok: true,
          status: 200,
          json: async () => makeTreeResponse([{ path: "main.ts", size: 100 }]),
          text: async () => "",
        } as unknown as Response;
      }
      if (url.includes("raw.githubusercontent.com/owner/repo/dev/main.ts")) {
        return {
          ok: true,
          status: 200,
          json: async () => "const x = 1;",
          text: async () => "const x = 1;",
        } as unknown as Response;
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const result = await fetchRepoFiles("https://github.com/owner/repo/tree/dev", { fetchImpl });
    expect(repoCalled).toBe(false); // should NOT have fetched repo metadata when ref is known
    expect(result.files).toHaveLength(1);
    expect(result.files[0].path).toBe("main.ts");
  });

  it("skips vendored and dependency directories", async () => {
    const fetchImpl = makeFetchImpl({
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": {
        status: 200,
        body: makeTreeResponse([
          { path: "src/app.py", size: 50 },
          { path: "node_modules/lodash/index.js", size: 50 },
          { path: "vendor/dep.go", size: 50 },
          { path: "dist/bundle.js", size: 50 },
          { path: "build/output.js", size: 50 },
          { path: ".git/config", size: 10 },
        ]),
      },
      "raw.githubusercontent.com/owner/repo/main/src/app.py": {
        status: 200,
        body: "print('hello')",
      },
    });

    const result = await fetchRepoFiles("https://github.com/owner/repo", { fetchImpl });
    expect(result.files).toHaveLength(1);
    expect(result.files[0].path).toBe("src/app.py");
  });

  it("skips blobs over 64 KB", async () => {
    const bigSize = 65 * 1024; // over 64 KB
    const fetchImpl = makeFetchImpl({
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": {
        status: 200,
        body: makeTreeResponse([
          { path: "src/tiny.py", size: 50 },
          { path: "src/huge.py", size: bigSize },
        ]),
      },
      "raw.githubusercontent.com/owner/repo/main/src/tiny.py": {
        status: 200,
        body: "x = 1",
      },
    });

    const result = await fetchRepoFiles("https://github.com/owner/repo", { fetchImpl });
    expect(result.files).toHaveLength(1);
    expect(result.files[0].path).toBe("src/tiny.py");
  });

  it("stops collecting after reaching 50-file cap", async () => {
    const files = Array.from({ length: 60 }, (_, i) => ({ path: `src/f${i}.py`, size: 100 }));
    const rawResponses: Record<string, { status: number; body: unknown }> = {
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": { status: 200, body: makeTreeResponse(files) },
    };
    // add raw responses for all 60 files
    for (let i = 0; i < 60; i++) {
      rawResponses[`raw.githubusercontent.com/owner/repo/main/src/f${i}.py`] = {
        status: 200,
        body: `# file ${i}`,
      };
    }
    const fetchImpl = makeFetchImpl(rawResponses);
    const result = await fetchRepoFiles("https://github.com/owner/repo", { fetchImpl });
    expect(result.files.length).toBeLessThanOrEqual(50);
  });

  it("stops collecting when total content exceeds 256 KB", async () => {
    // Each file is 64 KB; after 4 files we'd exceed 256 KB
    const chunkSize = 64 * 1024;
    const bigContent = "x".repeat(chunkSize);
    const files = Array.from({ length: 6 }, (_, i) => ({ path: `src/f${i}.py`, size: chunkSize }));

    const rawResponses: Record<string, { status: number; body: unknown }> = {
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": { status: 200, body: makeTreeResponse(files) },
    };
    for (let i = 0; i < 6; i++) {
      rawResponses[`raw.githubusercontent.com/owner/repo/main/src/f${i}.py`] = {
        status: 200,
        body: bigContent,
      };
    }

    const fetchImpl = makeFetchImpl(rawResponses);
    const result = await fetchRepoFiles("https://github.com/owner/repo", { fetchImpl });
    // Should stop before collecting all 6 files due to 256 KB cap
    expect(result.files.length).toBeLessThan(6);
    const totalBytes = result.files.reduce(
      (n, f) => n + new TextEncoder().encode(f.content).length,
      0
    );
    expect(totalBytes).toBeLessThanOrEqual(256 * 1024);
  });

  it("infers language from the most common extension", async () => {
    const fetchImpl = makeFetchImpl({
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": {
        status: 200,
        body: makeTreeResponse([
          { path: "a.ts", size: 50 },
          { path: "b.ts", size: 50 },
          { path: "c.ts", size: 50 },
          { path: "d.py", size: 50 },
        ]),
      },
      "raw.githubusercontent.com/owner/repo/main/a.ts": { status: 200, body: "const a = 1;" },
      "raw.githubusercontent.com/owner/repo/main/b.ts": { status: 200, body: "const b = 2;" },
      "raw.githubusercontent.com/owner/repo/main/c.ts": { status: 200, body: "const c = 3;" },
      "raw.githubusercontent.com/owner/repo/main/d.py": { status: 200, body: "x = 1" },
    });

    const result = await fetchRepoFiles("https://github.com/owner/repo", { fetchImpl });
    expect(result.language).toBe("typescript");
  });

  it("throws an error when zero source files are found", async () => {
    const fetchImpl = makeFetchImpl({
      "api.github.com/repos/owner/repo": { status: 200, body: makeRepoResponse("main") },
      "git/trees/main": {
        status: 200,
        body: makeTreeResponse([
          { path: "README.md", size: 200 },
          { path: "LICENSE", size: 100 },
          { path: "data.json", size: 50 },
        ]),
      },
    });

    await expect(fetchRepoFiles("https://github.com/owner/repo", { fetchImpl })).rejects.toThrow(
      "no scannable source files found in owner/repo"
    );
  });

  it("throws when the GitHub API returns 404 (repo not found)", async () => {
    const fetchImpl = makeFetchImpl({
      "api.github.com/repos/owner/nonexistent": { status: 404, body: { message: "Not Found" } },
    });

    await expect(
      fetchRepoFiles("https://github.com/owner/nonexistent", { fetchImpl })
    ).rejects.toThrow();
  });

  it("sends an Authorization: Bearer header on every fetch when a token is provided", async () => {
    const seenAuth: Array<string | null> = [];
    const fetchImpl = async (url: string, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      seenAuth.push(headers["authorization"] ?? null);
      const body =
        url.includes("git/trees/main") ? makeTreeResponse([{ path: "src/app.py", size: 50 }]) :
        url.includes("raw.githubusercontent.com") ? "print('hi')" :
        makeRepoResponse("main");
      return {
        ok: true, status: 200,
        json: async () => body,
        text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
      } as unknown as Response;
    };

    const result = await fetchRepoFiles("https://github.com/owner/repo", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      token: "ghp_secrettoken",
    });
    expect(result.files).toHaveLength(1);
    expect(seenAuth.length).toBe(3); // repo meta + tree + 1 raw blob
    expect(seenAuth.every((a) => a === "Bearer ghp_secrettoken")).toBe(true);
  });

  it("sends NO Authorization header when no token is provided", async () => {
    let sawAuth = false;
    const fetchImpl = async (url: string, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      if (headers["authorization"]) sawAuth = true;
      const body =
        url.includes("git/trees/main") ? makeTreeResponse([{ path: "src/app.py", size: 50 }]) :
        url.includes("raw.githubusercontent.com") ? "print('hi')" :
        makeRepoResponse("main");
      return {
        ok: true, status: 200,
        json: async () => body,
        text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
      } as unknown as Response;
    };

    await fetchRepoFiles("https://github.com/owner/repo", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(sawAuth).toBe(false);
  });
});
