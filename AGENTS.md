# AGENTS.md — AIHarness

## Project

AIHarness is a model-agnostic AI harness for scanning source code for security vulnerabilities, deployed on Cloudflare. It pairs deterministic SAST (Semgrep, running in a container) with LLM triage behind a swappable `ModelAdapter` interface. Built by Vladimir Kamenev for Chevron to demonstrate enterprise-grade, cloud-native AI-assisted vulnerability detection. The engine is fully deployed (P1a). See `README.md` for product overview and `ARCHITECTURE.md` for design depth.

Live: https://aiharness.degenito.ai

---

## Setup & Commands

```sh
npm install
npm test                 # vitest workspace — 62 tests (workerd pool + Node pool)
npx tsc --noEmit         # type-check src (currently clean)
npm run dev              # wrangler dev (local)
npm run deploy           # wrangler deploy — REQUIRES Docker daemon running (builds Semgrep image)
npm run migrate:local    # apply D1 migrations locally
npm run migrate:remote   # apply D1 migrations to production
```

---

## Architecture Map

```
src/index.ts            Entry point — Hono app, Env bindings, queue consumer handler
src/orchestrator/       Route handlers (POST /api/scans, GET /api/scans/:id, etc.) + zod validation
                        webhook.ts — PR-webhook bot (HMAC verify, scan changed files, post PR comment)
src/input-adapters/     git-url.ts — fetch a public GitHub repo's source (≤50 files / 256 KB)
src/integrations/       github-pr.ts — post findings as a PR comment
src/scan-runner/        runner.ts — ScanRunner Durable Object + container interaction
                        semgrep-normalize.ts — normalizes Semgrep JSON output
src/adapters/           model-adapter.ts — ModelAdapter interface
                        claude.ts — ClaudeAdapter (claude-opus-4-8, no temperature)
                        (OpenAI/Gemini: documented extension points; not yet shipped)
src/triage/             triageFindings, computeConfidence (evidence-based, not model self-rating)
src/report/             buildSarif (SARIF 2.1.0 + CWE taxonomies), recordAudit, hashPrompt
src/crypto/             envelope.ts — AES-GCM envelope encryption (DEK wrapped by KEK)
src/db/                 queries.ts — parameterized D1 queries only
src/schema.ts           zod schemas for request validation + input caps
integrations/
  github-action/        CI/CD composite action (scans in CI, uploads SARIF)
container/              Dockerfile (FROM semgrep/semgrep) + server.py (HTTP :8080, POST /scan)
migrations/             D1 SQL migrations
public/                 Static frontend (demo site, Matrix terminal, 3D diagram)
tests/                  Vitest test files
fixtures/               Test fixtures incl. vuln-sample/ (intentional planted vulnerabilities)
docs/integrations/      ci-cd.md, pr-webhook.md
```

Config files:
- `wrangler.jsonc` — production config (includes containers block with Dockerfile)
- `wrangler.test.jsonc` — test config WITHOUT containers block (vitest config reader rejects bare Dockerfile paths)
- `vitest.config.ts` — workerd pool (excludes SARIF schema test)
- `vitest.node.config.ts` — Node pool (ajv SARIF schema test only)
- `vitest.workspace.ts` — combines both

---

## Conventions

- **TypeScript strict + ESM** throughout.
- **Zod** for all request/response validation; see `src/schema.ts` and `src/orchestrator/validate.ts`. Input caps: max 50 files, max 256 KB total.
- **Parameterized D1 queries only** — never string-concatenate SQL.
- **XSS-safe rendering** — all user-supplied finding fields rendered via `textContent`, never `innerHTML`.
- **Model adapter contract** — every adapter must validate output (zod), attempt bounded repair (3 attempts), then degrade to `"uncertain / needs review"`. Never hard-fail; propagate a `failed` scan status instead.
- **Evidence-based confidence** — computed from corroboration, never from the model's self-reported confidence score:
  - deterministic + LLM-confirmed → `high`
  - deterministic + LLM-uncertain → `medium`
  - deterministic + LLM-refuted → `low`
  - model-only → `low` / `"needs review"`
- **Prompt-injection defense** — scanned code is passed as data inside `BEGIN_CODE_WINDOW`/`END_CODE_WINDOW` delimiters; the system prompt instructs the model to treat content as data only and output strict JSON. Do not weaken this boundary.
- **Secrets via wrangler** — `wrangler secret put KEK` / `wrangler secret put DEMO_ANTHROPIC_KEY`. Local dev: `.dev.vars` (gitignored). Never commit keys.

---

## Testing Notes

- There are two vitest projects because **ajv is CommonJS and cannot load in workerd** — the SARIF-schema validation test runs in a Node project (`vitest.node.config.ts`). The workspace (`vitest.workspace.ts`) glues them together; `npm test` runs both.
- Tests reference `wrangler.test.jsonc` (no `containers` block) — the workerd vitest config reader rejects raw Dockerfile paths; the DO binding is preserved so DO-based tests still work.
- **Each test must use UNIQUE D1 row ids** — D1 storage is shared across tests (`isolatedStorage: false`). Colliding UUIDs will cause flaky failures.
- The container scan and real model API calls are **not unit-tested** — they are verified at deploy time. Tests override `scanFn` and `makeAdapter` with stubs/mocks.

---

## Deploy & Operations Gotchas

1. **Docker daemon must be running** before `npm run deploy`. Wrangler builds the Semgrep container image locally. Without Docker the deploy fails immediately.

2. **Do NOT pass `temperature` to `claude-opus-4-8`**. That model deprecates the parameter and returns HTTP 400. Omit it entirely. Determinism is anchored via the pinned model id + a recorded prompt hash in the audit log.

3. **The container requires `enableInternet: true`** so Semgrep can fetch the `p/default` ruleset at scan time. Semgrep also **redacts matched source lines to "requires login"** for unauthenticated community use — always build the model's code window from the real source files loaded from R2, never from Semgrep's `lines` field.

4. **Cloudflare bot protection 403s the `Python-urllib` user-agent** — use a browser-like UA string when making API test requests against the live Worker.

5. **Worker Custom Domain can exist with a missing DNS record** — if the custom domain shows as attached but the domain doesn't resolve, re-provision the DNS record by cycling the binding: `DELETE /accounts/{id}/workers/domains/{domainId}` then `PUT /accounts/{id}/workers/domains`.

6. **Production config vs test config** — `wrangler.jsonc` (production, has containers block) vs `wrangler.test.jsonc` (tests, no containers block). Use the correct one; mixing them causes parse errors or missing bindings.

---

## Security Rules for Agents

- **Never log or persist API keys** — the BYO key is envelope-encrypted (AES-GCM, DEK wrapped by KEK) and stored only for the duration of the job. The `finally` block shreds the key unconditionally. Do not break this invariant.
- **Preserve the envelope-encryption + key-shred-in-finally invariant** in `src/scan-runner/runner.ts`. Any refactor that might skip the `finally` is a security regression.
- **Keep the prompt-injection (code-as-data) invariant** — the `BEGIN_CODE_WINDOW`/`END_CODE_WINDOW` delimiters and the "treat as data" system-prompt instruction must not be removed or weakened.
- **Keep XSS-safe rendering** — never switch finding-field rendering from `textContent` to `innerHTML`.
- **Do not weaken size caps** — the 50-file / 256 KB limits exist to prevent abuse of the demo key.
- **The demo endpoint is intentionally unauthenticated** (authN/RBAC is P3, not yet built). Do not assume auth middleware exists. Scan ids are unguessable UUIDv4s; that is the current access control for demo results.

---

## DO NOT

- Commit secrets or `.dev.vars`.
- Switch `ScanRunner` to inherit from the `@cloudflare/containers` `Container` base class — its constructor throws under vitest. Use the low-level `this.ctx.container` API (`getTcpPort(8080).fetch`) as currently implemented.
- Add a `temperature` parameter to the Claude API call.
- Build the model code window from Semgrep's `lines` field — it is redacted for unauthenticated use.
- Run `npm run deploy` without Docker running.
- Use string-concatenated SQL — parameterized queries only.

---

## Roadmap

- **P1a** — done and deployed: orchestrator + ScanRunner (DO + Container + Semgrep) + Claude adapter + envelope key vault + SARIF 2.1.0 + demo site.
- **P1b** — done: Git repo URL input (`src/input-adapters/git-url.ts`); CI/CD GitHub Action (`integrations/github-action/`); PR-webhook bot (`src/orchestrator/webhook.ts` — requires user to set `GITHUB_WEBHOOK_SECRET` + `GITHUB_TOKEN` and register a GitHub App to activate).
- **P2** — OpenAI + Gemini adapters (documented extension points; not yet shipped) + model selector + adversarial self-verify.
- **P3** — RBAC/auth + per-tenant isolation + diff/baseline/suppression; secret scanning + dependency/SCA (OSV); result caching.
- **P4** — published benchmark (precision/recall), policy/compliance profiles (ASVS L2, IEC 62443, CWE Top 25), private/air-gap model option, prompt-injection test suite.

See `README.md` and `ARCHITECTURE.md` for full roadmap detail.

---

Built by Vladimir Kamenev for Chevron.
