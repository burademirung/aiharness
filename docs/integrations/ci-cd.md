# CI/CD Integration

AIHarness can be embedded directly in your continuous integration pipeline so
that every push or pull request is automatically scanned for AI/LLM security
issues.

## GitHub Actions (recommended)

The packaged **AIHarness GitHub Action** is the easiest way to integrate.  It:

- Collects source files from your repository.
- Sends them to the AIHarness API for analysis.
- Writes results as **SARIF 2.1.0** and uploads them to the GitHub
  **Security > Code scanning** tab.
- Optionally fails the job when findings exceed a configurable severity
  threshold.

See [`integrations/github-action/`](../../integrations/github-action/README.md)
for full documentation, including inputs, an example workflow, and notes on
using a BYO API key.

### Quick start

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: your-org/aiharness/.github/actions/scan@v1
    with:
      language: python
      fail-on-severity: high
      api-key: ${{ secrets.AIHARNESS_API_KEY }}
```

## Other CI systems (generic API)

For GitLab CI, CircleCI, Jenkins, or any other CI system, use the AIHarness
REST API directly:

1. **Submit a scan**

   ```bash
   SCAN_ID=$(curl -sf -X POST https://aiharness.degenito.ai/api/scans \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $AIHARNESS_API_KEY" \
     -d '{"language":"python","repoUrl":"https://github.com/your-org/your-repo"}' \
     | jq -r '.id')
   ```

2. **Poll for completion**

   ```bash
   while true; do
     STATUS=$(curl -sf "https://aiharness.degenito.ai/api/scans/$SCAN_ID" \
       | jq -r '.scan.status')
     [ "$STATUS" = "completed" ] && break
     [ "$STATUS" = "failed" ] && exit 1
     sleep 2
   done
   ```

3. **Fetch SARIF**

   ```bash
   curl -sf "https://aiharness.degenito.ai/api/scans/$SCAN_ID/sarif" \
     -o aiharness.sarif
   ```

Upload `aiharness.sarif` to your CI system's security report ingestion
(e.g., GitLab's `artifacts:reports:sast`).

## API reference summary

| Endpoint | Method | Description |
|---|---|---|
| `/api/scans` | POST | Create a scan (`{language, files}` or `{language, repoUrl}`). Returns `{id}`. |
| `/api/scans/:id` | GET | Poll status. Returns `{scan:{status}, findings:[…]}`. |
| `/api/scans/:id/sarif` | GET | Download SARIF 2.1.0 for the completed scan. |

The `apiKey` field (or `Authorization: Bearer` header) is optional; the public
demo endpoint uses a shared rate-limited key as fallback.  For production
workloads, provide a dedicated key or self-host AIHarness.
