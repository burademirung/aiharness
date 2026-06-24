# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately to:

**Vladimir Kamenev**
Phone / Signal: 5123369618

Please include:
- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept code or request/response pairs)
- The potential impact and affected component(s)
- Any suggested remediation if known

**Expected response times:**
- Acknowledgement: within 2 business days
- Initial assessment and severity triage: within 5 business days
- Resolution timeline communicated: within 10 business days

Coordinated disclosure is appreciated. We will credit reporters in release notes unless anonymity is requested.

---

## Supported Standards Alignment

AIHarness is designed and evaluated against the following standards and frameworks:

| Standard | Reference |
|---|---|
| OWASP Top 10 (2021) | https://owasp.org/Top10/ |
| OWASP ASVS 5.0 | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP Top 10 for LLM Apps (2025) | https://genai.owasp.org/llm-top-10/ |
| CWE / CWE Top 25 (2024) | https://cwe.mitre.org/ · https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html |
| SARIF 2.1.0 (OASIS) | https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html |
| NIST SSDF SP 800-218 | https://csrc.nist.gov/pubs/sp/800/218/final |
| NIST SSDF SP 800-218A (AI systems) | https://csrc.nist.gov/pubs/sp/800/218/a/final |
| NIST AI RMF (AI 100-1) | https://www.nist.gov/itl/ai-risk-management-framework |
| NIST AI 600-1 Gen-AI Profile | https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence |
| NIST CSF 2.0 | https://www.nist.gov/cyberframework |
| SLSA v1.0 | https://slsa.dev/ |
| CycloneDX SBOM | https://cyclonedx.org/ |
| CISA SBOM Guidance | https://www.cisa.gov/sbom |
| ISO/IEC 27001 | https://www.iso.org/standard/27001 |
| ISO/IEC 42001:2023 (AI Management) | https://www.iso.org/standard/42001 |
| SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 |
| ISA/IEC 62443 (OT/ICS) | https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards |

> **Note on EO 14110:** Executive Order 14110 ("Safe, Secure, and Trustworthy AI") was revoked on 2025-01-20. AIHarness aligns to NIST SSDF and NIST AI RMF on technical merit, not the EO.

---

## Security Design Invariants

The following security properties are enforced by design and reviewed on every change:

### Key and Secret Handling
- **BYO-key envelope encryption:** API keys are AES-GCM envelope-encrypted (per-job DEK wrapped by a KEK Worker secret with `wrapKey`/`unwrapKey` — least-privilege access). The plaintext key is never logged or persisted.
- **Key shredding:** The encrypted key record and decrypted key are deleted immediately after the scan job completes (or fails), in a `finally` block.
- **Secrets never in code or logs:** `.dev.vars` is gitignored. `KEK` and `DEMO_ANTHROPIC_KEY` are Cloudflare Worker secrets.

### Source Code Handling
- **Source TTL / deletion:** Uploaded source files are stored in R2 only for the duration of the scan job, then deleted. Queue messages carry only a `{scanId}` pointer — source code never transits the queue.
- **Never used for training:** Source code is sent to the LLM solely for security triage of the current scan and is not retained by the service for model training purposes.

### AI / LLM Security
- **Prompt-injection defense (OWASP LLM01):** Scanned code is passed as DATA inside `BEGIN_CODE_WINDOW`/`END_CODE_WINDOW` delimiters. The system prompt explicitly forbids following instructions found in code. The model is constrained to fill a strict JSON schema output only.
- **Evidence-based confidence:** Confidence scores are derived from corroboration between Semgrep (deterministic) and LLM outputs — never from the model's self-assessed confidence, which is unverifiable.
- **Never hard-fails:** Model output is schema-validated (zod) with a bounded 3-attempt repair loop. On unrecoverable model or container error, the scan degrades gracefully to `failed` status; it does not crash or expose internal state.

### Infrastructure
- **Container path-traversal guard:** The Semgrep container's Python HTTP server uses `realpath` containment to prevent path traversal in posted file paths.
- **XSS-safe rendering:** All finding fields (titles, descriptions, code snippets) are rendered via DOM `textContent`, not `innerHTML`.
- **Parameterized SQL:** All Cloudflare D1 queries use parameterized statements; no string interpolation of user-controlled values.

---

## Self-Scan Results (2026-06-24)

| Check | Result |
|---|---|
| Production dependency vulnerabilities | **0** |
| SARIF 2.1.0 schema validation (ajv, CI) | **Pass** |
| CycloneDX SBOM | **148 components generated** |
| Manual code review | **Clean** |

### Known Gap: Authentication / Authorization

The demo endpoint is currently **unauthenticated**. Access is mitigated by:
- Unguessable UUIDv4 scan IDs (no enumeration)
- BYO-key model (callers supply their own API key, or the demo key is used for the shared demo path only)

**Cloudflare Access is recommended before using AIHarness in any sensitive or production context.** AuthN/Z + RBAC + per-tenant isolation is on the roadmap (P3).

---

*Built by Vladimir Kamenev for Chevron.*
