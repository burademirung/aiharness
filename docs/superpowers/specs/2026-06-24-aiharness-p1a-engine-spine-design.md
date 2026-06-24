# AIHarness P1a — Engine Spine (Design / Spec)

> Scope: the **first end-to-end deployable slice**. One input, one deterministic engine, one model, real findings, SARIF out, deployed to the live Cloudflare account.
> Parent: [Master Design](./2026-06-24-aiharness-master-design.md). Status: approved 2026-06-24.

## Goal

A user pastes (or uploads) code in a minimal web UI → it is scanned by **Semgrep** in a Container → findings are triaged by the **Claude** adapter (CWE-grounded, code-as-data, schema-validated) → the result is returned as **SARIF 2.1.0** and rendered in a minimal results view, with live progress. Deployed and runnable on the live CF account.

**Out of scope for P1a** (later phases): secret/SCA scanning, SBOM, OpenAI/Gemini adapters, git/PR/API inputs, RBAC/multi-tenant, baseline/diff, policy profiles, the full marketing site, adversarial self-verify. Keep the seams for them; don't build them.

## In scope (and only this)

1. **Web UI (minimal)** — a single page on Pages: a code textarea + language select + "Scan" button; a results panel that streams progress and then shows findings (rule, CWE, severity, confidence, message, location) and a "Download SARIF" button.
2. **Orchestrator Worker (Hono)** — `POST /api/scans` (accepts code + language + model config), `GET /api/scans/:id` (status + result), `GET /api/scans/:id/stream` (SSE progress), `GET /api/scans/:id/sarif`. Validates input, enforces size caps, stores source in R2, writes a job row in D1, enqueues.
3. **BYO-key envelope encryption** — the Claude API key is provided per request; encrypted with a per-job DEK (DEK wrapped by a KEK held in a Worker secret), ciphertext stored in D1 scoped to the job, **deleted when the job completes**. Key is never logged, never persisted in cleartext.
4. **ScanRunner (Durable Object + Container)** — consumes the job, runs **Semgrep** (default ruleset, language-scoped) over the source, normalizes Semgrep output to internal `Finding` objects (ruleId, CWE, severity, location, message, snippet), emits SSE progress, persists state.
5. **AI Triage Worker** — for each Semgrep finding, calls the **Claude `ModelAdapter`** with a CWE-grounded prompt (code as delimited data; strict JSON-schema output). The adapter confirms/refutes, adds a plain-language explanation + remediation, and an **evidence-based confidence** (Semgrep+Claude-confirmed = high; Semgrep-only if Claude errors = medium). Output schema-validated with a bounded repair loop; on persistent invalid output the finding degrades to "needs-review" (scan still succeeds).
6. **Report module** — assemble **SARIF 2.1.0 + Errata 01**: `tool.driver` (name, version, rules), CWE via `taxonomies`, `results` with ruleId/level/message/locations/`partialFingerprints`, and `properties` for confidence + AI rationale. Store SARIF in R2; write an **audit record** to D1 (model id+version, prompt hash, Semgrep ruleset version, timestamps).

## ModelAdapter (P1a: Claude only)

```ts
interface ModelAdapter {
  readonly id: string;
  readonly capabilities: { maxContextTokens: number; supportsStructuredOutput: boolean; supportsSeed: boolean };
  analyze(input: TriageInput): Promise<TriageOutput>; // schema-validated, repaired, never throws past the repair budget
}
// TriageInput: { finding, codeWindow, cwe, policy }
// TriageOutput: { verdict: "confirmed"|"refuted"|"uncertain", confidence, severity, explanation, remediation }
```
- temperature 0; pinned model-version string; prompt hash recorded.
- code-as-data: system prompt treats anything inside the code delimiters as content, never instructions (OWASP LLM01).

## Data model (D1)

- `scans(id, status, language, created_at, completed_at, source_r2_key, sarif_r2_key, model_id, model_version, prompt_hash, ruleset_version)`
- `findings(id, scan_id, rule_id, cwe, severity, confidence, evidence, verdict, message, file, start_line, end_line)`
- `job_keys(scan_id, dek_wrapped, key_ciphertext, created_at)` — deleted on completion.
- `audit_log(id, scan_id, event, detail_json, at)`

## Limits / guardrails (P1a)

- Max input: e.g. 256 KB / 50 files (paste/zip). Larger → rejected with a clear message.
- Container tier: `standard` (4 GB) or custom; Semgrep run with a timeout.
- Subrequest batching for triage; per-scan token budget; skip generated/minified/binary files.
- Queue messages carry only the scan id + R2 key, never code.

## Acceptance criteria

1. Pasting a known-vulnerable snippet (e.g., a SQL-injection or command-injection sample) returns ≥1 finding tagged with the correct CWE, a confidence, and a remediation.
2. The returned SARIF validates against the **SARIF 2.1.0** JSON schema (golden-file + schema test).
3. Progress streams to the UI via SSE; final findings render with rule/CWE/severity/confidence.
4. The BYO Claude key is never written to logs or persisted in cleartext, and `job_keys` is empty after completion (test asserts deletion).
5. An invalid/garbled model response does not fail the scan — the finding degrades to "needs-review" and the scan completes (fault-injection test).
6. The whole flow runs deployed on the live CF account (orchestrator + DO/Container + Pages), not only locally.

## Testing strategy

- **Unit:** orchestrator input validation + size caps; envelope encrypt/decrypt + key deletion; Semgrep-output normalizer; SARIF builder (golden file); confidence calculator.
- **Adapter contract:** Claude adapter against a recorded fixture response; schema-validation + repair-loop + degrade-to-needs-review paths.
- **Integration:** scan a fixture containing planted vulnerabilities end-to-end; assert findings + valid SARIF.
- **Fault injection:** model returns invalid JSON → scan still completes; key always deleted.
- Local: Wrangler/Miniflare. Then deploy to live account and re-run the integration check against the deployed endpoint.

## Open implementation choices (resolve during planning, not blocking)

- Semgrep default ruleset + initial language set (proposed: JS/TS, Python, Java, Go).
- Container base image (Semgrep official image vs slim custom).
- Whether the Queue consumer or the orchestrator directly invokes the ScanRunner DO (proposed: Queue consumer → DO).
