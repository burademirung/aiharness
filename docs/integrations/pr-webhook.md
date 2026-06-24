# GitHub PR-webhook bot (input method #4)

AIHarness can scan the changed source files in a pull request and post the
findings back as a PR comment. It listens on:

```
POST https://aiharness.degenito.ai/api/webhook/github
```

> **Activation requires two Worker secrets** (`GITHUB_WEBHOOK_SECRET` and
> `GITHUB_TOKEN`). Until both are set, the endpoint returns `503 webhook not
> configured` and does nothing. This is by design — the bot will not run with a
> partial configuration.

## How it works

1. GitHub sends a `pull_request` event to the endpoint.
2. The Worker reads the **raw** body and verifies the `X-Hub-Signature-256`
   header — `sha256=` + HMAC-SHA256(`GITHUB_WEBHOOK_SECRET`, rawBody) — using a
   **constant-time** comparison. A missing or wrong signature is rejected with
   `401`.
3. `ping` events return `200 {ok:true}`. Only the `opened`, `synchronize`, and
   `reopened` actions are acted on; every other action/event returns `200` and
   is ignored.
4. For an acted-on PR, the bot fetches the changed files
   (`GET /repos/{owner}/{repo}/pulls/{number}/files`) using `GITHUB_TOKEN`,
   keeps the scannable source files (extension allowlist, non-removed), fetches
   each file's content at the PR head SHA, and applies the same caps as the
   other inputs (**50 files / 256 KB total**).
5. It enqueues a scan exactly like `POST /api/scans` (stores `{language,files}`
   in R2, creates the scan row, encrypts the demo key, enqueues `{scanId}`) and
   persists the PR context (`owner`, `repo`, `pr_number`, `head_sha`) in the
   `pr_jobs` table.
6. When the scan finishes successfully, `ScanRunner.runScan` looks up the
   `pr_jobs` row and posts a Markdown summary of the findings
   (`POST /repos/{owner}/{repo}/issues/{number}/comments`) — CWE, severity,
   confidence, `file:line`, and remediation. A posting failure is logged and
   does **not** fail the scan.

The scan uses the server-side demo Anthropic key (`DEMO_ANTHROPIC_KEY`). There
is no BYO-key path over the webhook.

## Setup

### 1. Create the webhook (repo webhook or GitHub App)

**Repo / org webhook** (simplest):

- Settings → Webhooks → Add webhook
- **Payload URL:** `https://aiharness.degenito.ai/api/webhook/github`
- **Content type:** `application/json`
- **Secret:** a strong random string — this is your `GITHUB_WEBHOOK_SECRET`.
- **Events:** "Let me select individual events" → check **Pull requests**.

**GitHub App** (recommended for multi-repo / org installs):

- Create a GitHub App with:
  - **Webhook URL:** `https://aiharness.degenito.ai/api/webhook/github`
  - **Webhook secret:** your `GITHUB_WEBHOOK_SECRET`
  - **Permissions:** Pull requests **Read & write** (to read changed files and
    post comments), Contents **Read** (to read file content at the head SHA).
  - **Subscribe to events:** **Pull request**.
- Install the App on the target repos. Use the App's **installation access
  token** as `GITHUB_TOKEN`.

### 2. Set the Worker secrets

```sh
# The same secret you configured on the GitHub side:
wrangler secret put GITHUB_WEBHOOK_SECRET

# A token (PAT or App installation token) with:
#   - pull_requests:write  (post the findings comment)
#   - repo / contents:read (read changed files + content at head SHA)
wrangler secret put GITHUB_TOKEN
```

Also ensure `DEMO_ANTHROPIC_KEY` and `KEK` are set, as for the other inputs.

### 3. Apply the migration

The `pr_jobs` table ships in `migrations/0002_pr_jobs.sql`:

```sh
npm run migrate:remote   # wrangler d1 migrations apply aiharness --remote
```

## Result

Open or push to a pull request in an installed repo and AIHarness comments the
findings on the PR within a minute or two (depending on scan time). Findings are
AI-assisted — treat them as a reviewer aid, not a gate.
