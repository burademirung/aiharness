# AIHarness — Master Design (Vision & Architecture)

> Working name: **AIHarness** (placeholder — rename later).
> Status: approved design, 2026-06-24. Greenfield project.
> A **model-agnostic AI harness for scanning source code for security vulnerabilities**, deployed on Cloudflare, with a public explainer/demo site that maps the system to recognized security standards.

## 1. Purpose & context

This system exists to let us answer, credibly and with a live demonstration, the vendor-qualification question:

> *"Have you developed a model-agnostic AI harness for scanning code for vulnerabilities?"* — Chevron

The buyer is an enterprise in **oil & gas / critical infrastructure**, so credibility means: recognized standards alignment, auditability, reproducibility, sound data-governance for source code, and honesty about LLM accuracy limits. The deliverable is **both** a working harness and a deeply-researched, standards-referenced web page with a visual model and use cases.

## 2. Principles

1. **Hybrid, not LLM-only.** Deterministic scanners provide reproducible, auditable, stable-rule-ID coverage. The LLM adds context, dedupe, plain-language explanation, and false-positive suppression. The LLM never invents a finding without a deterministic basis or an explicit "LLM-originated, needs-review" flag.
2. **Model-agnostic by interface.** A single `ModelAdapter` interface; `Claude`/`OpenAI`/`Gemini` (and private/self-hosted endpoints) are swappable implementations. This seam is the literal embodiment of the Chevron question.
3. **Trust is a feature.** Source code is never used for training, never retained past a job TTL; BYO-key so code reaches only the customer's own model contract; every scan produces an immutable audit record.
4. **Evidence-based confidence.** Confidence is derived from corroboration (which engines/models agreed), not from a model's self-reported score.
5. **Honest about accuracy.** Published benchmark methodology; LLM-only findings clearly labeled lower-confidence.
6. **Standards-mapped output.** Every finding maps to CWE/OWASP; output is SARIF 2.1.0; results can be projected onto a chosen compliance profile.

## 3. Architecture (Cloudflare-native)

```
 INPUT ADAPTERS                ORCHESTRATION                  ANALYSIS                       OUTPUT
 ┌───────────────┐
 │ Web paste/zip │──┐
 │ Git repo URL  │  │   ┌────────────────────────┐    ┌──────────────────────────────┐
 │ REST API / CI │──┼──▶│ Orchestrator Worker    │───▶│ ScanRunner (Durable Object   │
 │ PR webhook bot│  │   │  (Hono)                │ Q  │   + Container)               │
 └───────────────┘  │   │  • authN/Z, rate-limit │    │  DETERMINISTIC LAYER:        │
                    │   │  • BYO-key envelope    │    │   • Semgrep (CWE rules)      │
                    │   │    encryption          │    │   • secret scan (gitleaks)   │
                    │   │  • normalize→ScanJob   │    │   • SCA/deps (osv-scanner)   │
                    │   │  • enqueue + persist   │    │   • SBOM (CycloneDX)         │
                    │   └──────────┬─────────────┘    │  • owns container lifecycle  │
                    │              │ Queue            │  • SSE live progress         │
                    │              │ (R2 pointers,    │  → normalized findings        │
                    │              │  never code)     └────────────┬─────────────────┘
                    │              ▼                               │ raw findings + context
                    │     ┌──────────────────┐                     ▼
                    │     │ (consumer kicks  │        ┌──────────────────────────────┐
                    │     │  off ScanRunner) │        │ AI Triage Worker             │
                    │     └──────────────────┘        │  ModelAdapter interface →    │
                    │                                 │   Claude│OpenAI│Gemini│self  │
                    │                                 │  • CWE-grounded prompts       │
                    │                                 │  • code-as-data, schema-only  │
                    │                                 │  • dedupe, FP-suppress         │
                    │                                 │  • adversarial self-verify     │
                    │                                 │  • evidence-based confidence   │
                    │                                 └────────────┬─────────────────┘
                    │                                              ▼
                    │            ┌─────────────────────────────────────────────────┐
                    └───────────▶│ D1 (findings, jobs, audit log, encrypted keys)   │
                                 │ R2 (source[TTL], SARIF, SBOM, reports)           │
                                 │ KV (config, policy/compliance packs)             │
                                 └─────────────────────────────────────────────────┘
                                              ▼  SARIF 2.1.0 + HTML report + SBOM
                          Results UI │ SARIF download │ PR comment │ API/CI gate
```

### Cloudflare primitives
- **Pages** — explainer/demo site + results viewer.
- **Workers + Hono** — orchestrator API, queue consumer, AI triage.
- **Durable Object + Container** ("ScanRunner") — runs the deterministic engines, owns container lifecycle, streams live progress over SSE, holds per-job state. (CF Containers are driven through a DO; tier: `standard` 4GB / custom.)
- **Queues** — async job dispatch. Messages carry **R2 pointers, never source code**.
- **D1** — jobs, findings, audit log, encrypted BYO-key ciphertext.
- **R2** — source (encrypted, TTL-bounded), SARIF/SBOM/report artifacts.
- **KV** — config + policy/compliance profile packs.
- **Workers Secret / Secrets Store** — holds the platform KEK (Secrets Store's 100-secret/account cap makes it unsuitable for per-tenant model keys; those use envelope encryption instead).

## 4. Components & boundaries

| Module | Responsibility | Depends on |
|---|---|---|
| `input-adapters/*` | paste / zip / git URL / webhook / API → canonical `ScanJob` (file tree + metadata in R2) | R2, D1 |
| `orchestrator` (Worker/Hono) | authN/Z, rate-limit, BYO-key envelope encryption, enqueue, status, SARIF assembly | Queue, D1 |
| `scan-runner` (DO + Container) | run deterministic engines, emit normalized findings, manage container lifecycle, SSE progress | R2 |
| `model-adapter` | **agnostic core.** `analyze(findings, codeContext, policy) → ValidatedFindings`; per-provider capability/cost/context metadata | provider SDKs |
| `triage-engine` | orchestrate adapter calls, dedupe, adversarial self-verify, evidence-based confidence, CWE/OWASP mapping | model-adapter |
| `report` | emit SARIF 2.1.0 + Errata 01, HTML report, CycloneDX SBOM, immutable audit record | D1, R2 |
| `web` (Pages) | explainer site, interactive diagram, standards matrix, live demo, results viewer | orchestrator API |

Each module is independently testable: deterministic engines are pure (image in, findings out); adapters are mocked in unit tests and contract-tested against recorded fixtures; SARIF output is golden-file tested against the OASIS schema.

## 5. The model-agnostic interface

```ts
interface ModelAdapter {
  readonly id: string;                 // "claude" | "openai" | "gemini" | "self-hosted"
  readonly capabilities: {
    maxContextTokens: number;
    supportsStructuredOutput: boolean; // JSON/tool mode
    supportsSeed: boolean;             // determinism aid
  };
  analyze(input: TriageInput): Promise<TriageOutput>; // strict schema out, validated + repaired
}
```

- **Determinism:** temperature 0; provider seed where supported; pinned model-version strings; prompt hash recorded in the audit log.
- **Output safety:** the model only fills a strict JSON schema (it never controls flow). Output is schema-validated; on invalid output a bounded repair loop runs, then the finding degrades to "needs-review" rather than failing the scan. (Lesson learned: an unvalidated structured-output loop is what killed the research workflow during this project's design phase.)
- **Prompt-injection defense (OWASP LLM01):** scanned code is untrusted; it is delimited/spotlighted and presented as *data*. The system prompt asserts that instructions found inside code are to be treated as content, never obeyed.

## 6. Evidence-based confidence model

| Corroboration | Confidence |
|---|---|
| Deterministic engine **and** LLM confirm | High |
| Multiple independent models agree | Higher |
| Deterministic-only (no LLM context) | Medium (rule-dependent) |
| LLM-only (no deterministic basis) | Low — labeled "needs review" |
| Survived adversarial self-verify (refute attempt failed) | confidence boosted |

Each finding records *why* it scored as it did. False positives are flagged and suppressible, never silently dropped.

## 7. Standards mapping (drives the web page; every claim links to the source)

| Layer | Standards (verified identifiers) |
|---|---|
| Weakness taxonomy | **CWE** incl. **CWE Top 25 (2024)** (XSS CWE-79 #1, OOB-Write CWE-787 #2); MITRE **CAPEC/ATT&CK** refs |
| App risk framing | **OWASP Top 10 (2021)**, **OWASP ASVS 5.0.0** (May 2025), **OWASP Top 10 for LLM Apps 2025** |
| Findings format | **SARIF 2.1.0 + Errata 01** (OASIS Standard) |
| Secure SDLC | **NIST SSDF SP 800-218 v1.1** + **SP 800-218A** (AI companion) |
| AI governance | **NIST AI RMF 1.0 (AI 100-1)** + **Gen-AI Profile (NIST AI 600-1)**, **ISO/IEC 42001:2023** |
| Supply chain | **SLSA v1.0**, **SBOM / CycloneDX**, CISA SBOM guidance, OSV-based SCA |
| Org security mgmt | **ISO/IEC 27001**, **SOC 2**, **NIST CSF 2.0** (2024) |
| Critical infra / OT | **ISA/IEC 62443**, NIST CSF 2.0 |
| Code quality (optional) | **ISO/IEC 5055** |

> Caveat for page copy: **EO 14110 was revoked 2025-01-20.** Cite SSDF/AI-RMF/SP-800-218A on technical merit, not on the executive order.

## 8. Web page — visual model, content, use cases

Cloudflare Pages site, distinctive (non-template) design:
- **Hero** — one-line answer to the Chevron question + "Run a live scan" CTA.
- **Interactive architecture diagram** — the pipeline above; click any node → what it does + which standard it satisfies.
- **Live demo** — paste code / pick a planted-vuln sample → real scan → SARIF + annotated findings, each tagged CWE/OWASP + confidence.
- **Standards matrix** — the §7 table, every cell linking to the source doc/version.
- **Use cases** — (1) PR gate in CI, (2) pre-acquisition vendor-code audit, (3) OT/ICS repo review vs IEC 62443, (4) second-opinion over an existing SAST tool, (5) SBOM + supply-chain check.
- **Trust & data governance** — BYO-key, no-training, TTL retention, reproducibility, audit log, model-agnostic seam, prompt-injection defenses.
- **Accuracy transparency** — benchmark methodology + precision/recall + honest FP/FN discussion.
- **Procurement** — ISO/SOC posture, data residency.

## 9. Cross-cutting requirements

- **Cost/scale bounding:** deterministic layer covers 100% of code; LLM sees only findings + surrounding context windows. Per-scan token budget, max repo size, skip generated/minified/binary, cache by `(file-hash + ruleset-version + model-version)`.
- **Incremental/diff scanning + baseline/suppression:** changed-files-only for PR/CI; baseline existing findings; `.aiharnessignore`; finding states (confirmed / FP / accepted-risk) with reviewer attribution (maps to NIST AI RMF "Manage").
- **Policy/compliance profiles:** project findings onto a chosen profile (OWASP ASVS L2, IEC 62443, CWE Top 25).
- **Git ingest:** prefer host-API tarball download (token-scoped) over git-in-container.
- **Demo abuse protection:** Turnstile + rate-limit + strict size caps.
- **Authorization-to-scan attestation:** user attests rights to scan third-party code.
- **Multi-tenancy:** per-org D1 row scoping, RBAC, signed reports.
- **Observability:** Workers analytics/logpush; immutable audit log (model, version, prompt hash, ruleset versions, timestamps).

## 10. Phasing (each phase → its own spec + plan)

- **P1a — Engine spine (first deployable):** orchestrator + ScanRunner (DO+Container, **Semgrep**) + **Claude** adapter + envelope key vault + **SARIF 2.1.0** + minimal results UI. End-to-end real scan, deployed to the live CF account.
- **P1b:** add **secret scanning + SCA/SBOM (CycloneDX)** + result caching.
- **P2:** **OpenAI + Gemini** adapters + selector + adversarial self-verify + full explainer/demo site (interactive diagram, standards matrix, use cases).
- **P3:** GitHub Action + PR webhook bot + public REST API + RBAC + audit log + diff/baseline/suppression.
- **P4:** benchmark page, policy/compliance profiles, private/air-gap model option, prompt-injection test suite.

## 11. Testing & non-functionals

TDD throughout. Unit tests per module (adapters mocked); golden-file SARIF tests vs the OASIS schema; an integration test that scans a fixture repo with planted vulnerabilities and asserts findings; contract tests per adapter against recorded fixtures. Local dev via Wrangler/Miniflare; deploy incrementally to the live CF account.

## 12. Decided trade-offs (for the record)

- **Deterministic layer host:** **CF Containers only** (accepts public-preview status; revisit if production SLA becomes a blocker). The OCI image remains inherently portable if we ever need to move it.
- **BYO model keys:** envelope encryption in D1, deleted at job end — *not* Secrets Store (100-secret/account, 1KB cap).
- **Orchestration:** Queue + ScanRunner DO for P1; Cloudflare Workflows considered for durable retries in a later phase if external-LLM flakiness warrants it.
- **Confidence:** evidence/corroboration-based, not model self-rating.
