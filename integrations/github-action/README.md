# AIHarness GitHub Action

Run an [AIHarness](https://aiharness.degenito.ai) AI/LLM security scan directly
in your GitHub Actions pipeline. Findings are written as SARIF 2.1.0 and
automatically uploaded to the repository's **Security > Code scanning** tab.

## What it does

1. Collects source files from your workspace (filtered by language extension,
   skipping `node_modules`, `vendor`, `dist`, `build`, `.git`, etc.).
2. POSTs the files to the AIHarness API for analysis.
3. Polls until the scan completes (up to 5 minutes).
4. Writes a SARIF file and prints a findings summary to the job log.
5. Uploads the SARIF to GitHub via `github/codeql-action/upload-sarif` so
   findings appear in the Security tab, even if the job itself fails.
6. Optionally fails the job if any finding meets or exceeds a configurable
   severity threshold.

## Example workflow

```yaml
name: AIHarness Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  aiharness:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: AIHarness Scan
        uses: your-org/aiharness/.github/actions/scan@v1
        with:
          language: python
          paths: 'src tests'
          fail-on-severity: high
          api-key: ${{ secrets.AIHARNESS_API_KEY }}
```

> **Tip:** Replace `your-org/aiharness/.github/actions/scan@v1` with the path
> where you publish or copy the action.  If you self-host AIHarness, set
> `api-url` to your instance's base URL.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-url` | No | `https://aiharness.degenito.ai` | Base URL of the AIHarness API. Set to your self-hosted instance if applicable. |
| `api-key` | No | _(empty)_ | API key for authenticated access. Pass via a repository secret (see below). |
| `language` | No | `python` | Primary language of the codebase. Supported: `python`, `javascript`, `typescript`, `java`, `go`, `ruby`, `php`, `c`, `cpp`, `csharp`, `rust`. |
| `paths` | No | `.` | Space-separated list of paths (relative to workspace root) to scan. |
| `fail-on-severity` | No | `high` | Fail the job if any finding is at or above this severity. Values: `critical`, `high`, `medium`, `low`, `none`. Use `none` to never fail. |
| `max-files` | No | `50` | Maximum number of source files sent to the API. |
| `sarif-file` | No | `aiharness.sarif` | Output path for the SARIF file (relative to workspace). |

## Using a BYO API key

Store your key as a repository secret (Settings > Secrets and variables >
Actions > New repository secret), then reference it in the workflow:

```yaml
api-key: ${{ secrets.AIHARNESS_API_KEY }}
```

## Notes

- **SARIF in the Security tab:** The upload step runs with `if: always()`, so
  findings are uploaded even if the scan step fails the job.  The
  `security-events: write` permission must be granted in the workflow (shown in
  the example above).

- **Public demo API:** The default endpoint (`https://aiharness.degenito.ai`)
  is a rate-limited, unauthenticated demo.  For production use, either provide
  an `api-key` or self-host the AIHarness harness and point `api-url` at your
  instance.

- **File limits:** By default the action sends up to 50 files, each capped at
  256 KB.  Increase `max-files` if your project is larger; be aware that larger
  payloads take longer to scan.

- **Supported extensions:** `.py .js .ts .jsx .tsx .java .go .rb .php .c .cpp .cs .rs`

- **Skipped directories:** `node_modules`, `vendor`, `dist`, `build`, `.git`,
  `__pycache__`, `.venv`, `venv`, `env`, `.mypy_cache`, `.pytest_cache`,
  `coverage`.
