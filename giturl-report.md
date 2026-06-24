# GitHub URL Input Adapter — Design Report

## Adapter Design (`src/input-adapters/git-url.ts`)

Two exported functions:

- **`parseGitHubUrl(url)`** — pure URL parser. Accepts `https://github.com/{owner}/{repo}`, optional `.git` suffix, optional `/tree/{ref}` (including refs with slashes like `feature/branch`). Returns `{ owner, repo, ref? }` or `null` for non-GitHub / malformed input.

- **`fetchRepoFiles(url, { fetchImpl? })`** — fetches source files from a public repo via the GitHub REST API (no token, `user-agent: aiharness`). Steps:
  1. Parse URL via `parseGitHubUrl`.
  2. If no ref in URL: `GET /repos/{owner}/{repo}` to resolve `default_branch`.
  3. `GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1` to list all blobs.
  4. Filter: extension allowlist (py/js/jsx/ts/tsx/java/go/rb/php/c/cpp/cs/rs), skip vendored dirs (node_modules, vendor, dist, build, .git), skip blobs >64 KB.
  5. Fetch raw content (raw.githubusercontent.com) until 50-file OR 256 KB cap is hit (whichever comes first). Files that 404 are silently skipped.
  6. Infer `language` from most-common extension among collected files; defaults to `"python"`.
  7. Throw if zero source files found.

  `fetchImpl` is injectable (defaults to global `fetch`) for deterministic unit tests with no network.

## Caps Handling

- Blobs >64 KB are filtered out at the tree stage (before fetching).
- File count cap (50) and total-bytes cap (256 KB) are checked during the sequential fetch loop; the loop breaks as soon as either is exceeded.
- These caps match the existing `validateScanRequest` limits for the files-paste path.

## Schema Changes (`src/schema.ts`)

- `files` is now `optional()` (was `min(1)` required).
- `repoUrl: z.string().url().optional()` added.
- Mutual-exclusivity enforced in `validateScanRequest`: at least one of `files` (non-empty) or `repoUrl` must be present; neither → 400 "provide files or a repoUrl".

## Routes (`src/orchestrator/routes.ts`)

- If `repoUrl` is set and `files` is absent/empty, calls `fetchRepoFiles(repoUrl)` to get `{ language, files }` before the existing R2-store/enqueue path.
- Errors from `fetchRepoFiles` (repo not found, no source files) are caught and returned as 400.
- The pipeline downstream is unchanged: it consumes `{ language, files }` from R2 regardless of origin.

## UI Mode (`public/index.html` + `public/app.js`)

- Segmented control with two buttons: **"Paste code"** (default) and **"GitHub repo URL"**.
- Buttons update `aria-pressed` and toggle panels.
- In repo mode: `POST { language, repoUrl }` (no `files`); language selector is still available (passed as a hint, overridden by adapter's inferred language on the server).
- In paste mode: existing behavior unchanged.
- "Load sample" button is hidden in repo mode.
- `node --check public/app.js` passes (no syntax errors).
- `styles.css` adds `.input-mode` / `.mode-btn` / `.mode-btn-active` matching the existing light + Matrix-terminal palette.

## Tests

### New: `tests/input-adapters/git-url.test.ts` (17 tests)
- `parseGitHubUrl`: 8 cases (basic, /tree/ref, slashed ref, .git suffix, non-GitHub, no repo segment, invalid string, empty string).
- `fetchRepoFiles` (fake `fetchImpl`): collects allowlisted files, skips vendored dirs, skips blobs >64 KB, 50-file cap, 256 KB cap, language inference, throws on zero source files, throws on 404.

### Extended: `tests/orchestrator/validate.test.ts` (+3 tests)
- `repoUrl`-only accepted; neither files nor repoUrl rejected (400, message matches "provide files or a repoUrl"); both accepted.
