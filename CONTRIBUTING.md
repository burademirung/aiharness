# Contributing to AIHarness

Thank you for your interest in contributing. AIHarness is a model-agnostic AI security-scanning harness built on Cloudflare Workers + Durable Objects + Containers. Contributions that improve correctness, coverage, security invariants, or model-adapter support are especially welcome.

---

## Prerequisites

| Tool | Notes |
|---|---|
| **Node.js 20+** | Required for the TypeScript build and test runner |
| **Docker** | Required for `wrangler deploy` only (builds the Semgrep container image) — not needed for tests |
| **Cloudflare account + Wrangler** | Required for deployment (`wrangler deploy`, `wrangler secret put`) |

---

## Setup

```bash
npm install
```

Local secrets go in `.dev.vars` (gitignored — never commit this file):

```ini
KEK=<your-base64-kek>
DEMO_ANTHROPIC_KEY=sk-ant-...
```

---

## Running Tests

```bash
npm test
```

This runs the **Vitest workspace**, which comprises two separate Vitest projects:

1. **Workers/workerd project** (`vitest.config.ts`) — runs tests in the `@cloudflare/vitest-pool-workers` pool (workerd runtime). Covers the orchestrator, scan runner, adapter, triage, report, crypto, and DB layers. Uses `wrangler.test.jsonc` (the `containers` block is intentionally absent — container interaction is deploy-verified, not unit-tested).

2. **Node project** (`vitest.node.config.ts`) — runs the SARIF 2.1.0 schema-validation test in a plain Node environment. This project exists because `ajv` is CommonJS and cannot be loaded inside the workerd runtime.

Each test generates a unique D1 row ID (UUID) so tests are isolated and can run in any order.

**Type-check (no emit):**

```bash
npx tsc --noEmit
```

`src/` is expected to be clean. Fix any type errors before opening a PR.

**Local dev server:**

```bash
npm run dev
```

Runs `wrangler dev`. Note: the Semgrep container requires Docker running and internet access (`enableInternet: true`) to fetch the `p/default` ruleset.

---

## Code Conventions

- **TypeScript strict + ESM** throughout. No `any` without a comment explaining why.
- **Zod validation** for all external inputs (scan requests, model outputs). See `src/schema.ts` and `src/orchestrator/validate.ts`.
- **Parameterized D1 queries only.** Never interpolate user-controlled values into SQL strings. See `src/db/queries.ts`.
- **XSS-safe rendering.** All user-supplied or model-generated content must be rendered via `textContent`, not `innerHTML`. This applies to the frontend in `public/`.
- **Adapter invariants.** Model adapters in `src/adapters/` must implement the `ModelAdapter` interface: `validate → repair (up to 3 attempts) → degrade` on bad output. Confidence must be evidence-based (corroboration between Semgrep and LLM), never the model's self-rating.
- **Never hard-fail.** Errors in the scan pipeline must result in a graceful `failed` status on the scan record, not an unhandled exception or crash.
- **Never commit secrets.** `.dev.vars` is gitignored. Do not add `KEK`, API keys, or any credential to any committed file.

---

## Branch and PR Flow

1. Fork the repo and create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature
   ```
2. Make your changes, keeping commits small and focused.
3. Use **Conventional Commit** messages:
   - `feat:` new capability
   - `fix:` bug fix
   - `refactor:` internal restructuring
   - `test:` test-only changes
   - `docs:` documentation only
   - `chore:` tooling / config
4. Ensure `npm test` and `npx tsc --noEmit` both pass locally.
5. Open a PR against `main`. Run `npm test` and `npx tsc --noEmit` locally to confirm all checks pass before requesting review.
6. A maintainer will review. Address feedback, then request re-review.

---

## Design Docs and Deploy Gotchas

Before making architectural changes, read:

- **`AGENTS.md`** — operational notes, deploy gotchas (Docker requirement, `claude-opus-4-8` rejecting `temperature`, Semgrep line-redaction workaround, Cloudflare bot-UA issue, custom-domain DNS re-provisioning, test config differences).
- **`docs/superpowers/specs/`** and **`docs/superpowers/plans/`** — design specs and implementation plans.
- **`docs/security/self-scan/`** — self-scan results and SARIF reports.

Key gotchas summary (see AGENTS.md for details):
- `npm run deploy` requires Docker running.
- `claude-opus-4-8` rejects the `temperature` parameter (HTTP 400) — do not add it.
- Tests use `wrangler.test.jsonc` (no `containers` block) and the Vitest workspace.

---

*Built by Vladimir Kamenev for Chevron.*
