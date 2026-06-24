/**
 * Git-URL input adapter — fetches a public GitHub repository's source files
 * using the public GitHub REST API (no token required).
 */

// Extensions we can scan, mapped to semgrep-ish language names
const EXT_TO_LANG: Record<string, string> = {
  py: "python",
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  java: "java",
  go: "go",
  rb: "ruby",
  php: "php",
  c: "c",
  cpp: "cpp",
  cs: "csharp",
  rs: "rust",
};

// Directories that are never worth scanning
const SKIP_DIRS = new Set(["node_modules", "vendor", "dist", "build", ".git"]);

const MAX_FILES = 50;
const MAX_TOTAL_BYTES = 256 * 1024;
const MAX_BLOB_BYTES = 64 * 1024;

export interface ParsedGitHubUrl {
  owner: string;
  repo: string;
  ref?: string;
}

/**
 * Parse a GitHub URL into { owner, repo, ref? }.
 * Accepts:
 *   https://github.com/{owner}/{repo}
 *   https://github.com/{owner}/{repo}.git
 *   https://github.com/{owner}/{repo}/tree/{ref}
 *   https://github.com/{owner}/{repo}/tree/{ref/with/slashes}
 *
 * Returns null for non-GitHub or malformed URLs.
 */
export function parseGitHubUrl(url: string): ParsedGitHubUrl | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  if (parsed.hostname !== "github.com") return null;

  // pathname: /{owner}/{repo}[.git][/tree/{ref}]
  const segments = parsed.pathname.split("/").filter(Boolean);
  if (segments.length < 2) return null;

  const owner = segments[0];
  let repo = segments[1];

  // Strip .git suffix
  if (repo.endsWith(".git")) repo = repo.slice(0, -4);

  // /tree/{ref} — ref may contain slashes
  let ref: string | undefined;
  if (segments.length >= 4 && segments[2] === "tree") {
    ref = segments.slice(3).join("/");
  }

  return { owner, repo, ref: ref || undefined };
}

export interface FetchRepoOptions {
  /** Injectable fetch implementation (default: global fetch). For testing. */
  fetchImpl?: typeof fetch;
}

export interface RepoFiles {
  language: string;
  files: Array<{ path: string; content: string }>;
}

/**
 * Fetch all scannable source files from a public GitHub repository.
 *
 * @throws Error if the URL is not a valid GitHub URL, the repo is not found,
 *   or no scannable source files are found.
 */
export async function fetchRepoFiles(
  url: string,
  { fetchImpl = fetch }: FetchRepoOptions = {}
): Promise<RepoFiles> {
  const parsed = parseGitHubUrl(url);
  if (!parsed) throw new Error(`Not a valid GitHub URL: ${url}`);

  const { owner, repo } = parsed;
  let ref = parsed.ref;

  // Step (a): resolve default branch if ref not given in URL
  if (!ref) {
    const repoRes = await fetchImpl(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: { "user-agent": "aiharness" },
    } as RequestInit);
    if (!repoRes.ok) {
      throw new Error(
        `GitHub API error fetching repo ${owner}/${repo}: ${repoRes.status}`
      );
    }
    const repoData = await repoRes.json() as { default_branch: string };
    ref = repoData.default_branch;
  }

  // Step (b): get the tree recursively
  const treeRes = await fetchImpl(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${ref}?recursive=1`,
    { headers: { "user-agent": "aiharness" } } as RequestInit
  );
  if (!treeRes.ok) {
    throw new Error(
      `GitHub API error fetching tree for ${owner}/${repo}@${ref}: ${treeRes.status}`
    );
  }
  const treeData = await treeRes.json() as {
    tree: Array<{ path: string; type: string; size?: number }>;
  };

  // Step (c): filter to source files by extension and skip vendored dirs
  const candidates = treeData.tree.filter((entry) => {
    if (entry.type !== "blob") return false;
    const { path } = entry;

    // Skip vendored/dep directories
    const parts = path.split("/");
    if (parts.some((p) => SKIP_DIRS.has(p))) return false;

    // Check extension allowlist
    const ext = path.split(".").pop()?.toLowerCase() ?? "";
    if (!EXT_TO_LANG[ext]) return false;

    // Skip blobs over 64 KB
    if (entry.size !== undefined && entry.size > MAX_BLOB_BYTES) return false;

    return true;
  });

  if (candidates.length === 0) {
    throw new Error(`no scannable source files found in ${owner}/${repo}`);
  }

  // Step (d): fetch raw content, respecting caps
  const files: Array<{ path: string; content: string; ext: string }> = [];
  let totalBytes = 0;

  for (const entry of candidates) {
    if (files.length >= MAX_FILES) break;

    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${entry.path}`;
    const rawRes = await fetchImpl(rawUrl, {
      headers: { "user-agent": "aiharness" },
    } as RequestInit);
    if (!rawRes.ok) continue; // skip files that can't be fetched

    const content = await rawRes.text();
    const byteLen = new TextEncoder().encode(content).length;

    if (totalBytes + byteLen > MAX_TOTAL_BYTES) break;

    const ext = entry.path.split(".").pop()?.toLowerCase() ?? "";
    files.push({ path: entry.path, content, ext });
    totalBytes += byteLen;
  }

  if (files.length === 0) {
    throw new Error(`no scannable source files found in ${owner}/${repo}`);
  }

  // Step (e): infer language from most-common extension
  const extCount: Record<string, number> = {};
  for (const f of files) {
    extCount[f.ext] = (extCount[f.ext] ?? 0) + 1;
  }
  const dominantExt = Object.entries(extCount).sort((a, b) => b[1] - a[1])[0][0];
  const language = EXT_TO_LANG[dominantExt] ?? "python";

  return {
    language,
    files: files.map(({ path, content }) => ({ path, content })),
  };
}
