import type { Env } from "../index";
import type { Finding, PrJob } from "../types";

/**
 * Build a Markdown summary of findings to post on a PR.
 * Exported for unit testing.
 */
export function buildCommentBody(findings: Finding[], headSha: string): string {
  const shortSha = headSha.slice(0, 7);
  if (findings.length === 0) {
    return `## AIHarness security scan\n\nNo findings on \`${shortSha}\`. ✅`;
  }

  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
  );

  const lines: string[] = [];
  lines.push(`## AIHarness security scan`);
  lines.push("");
  lines.push(
    `Scanned changed files at \`${shortSha}\` — **${findings.length}** finding${findings.length === 1 ? "" : "s"}.`
  );
  lines.push("");
  lines.push("| Severity | Confidence | CWE | Location | Issue |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const f of sorted) {
    const loc = `\`${f.file}:${f.startLine}\``;
    const cwe = f.cwe ?? "—";
    const msg = (f.message || f.ruleId).replace(/\|/g, "\\|").replace(/\n/g, " ");
    lines.push(
      `| ${f.severity} | ${f.confidence ?? "—"} | ${cwe} | ${loc} | ${msg} |`
    );
  }
  lines.push("");

  // Per-finding detail (explanation + remediation) in collapsible sections.
  for (const f of sorted) {
    lines.push(`<details><summary>${f.severity.toUpperCase()} — ${f.file}:${f.startLine} (${f.cwe ?? "no CWE"})</summary>`);
    lines.push("");
    if (f.explanation) lines.push(`**Why:** ${f.explanation}`);
    if (f.remediation) lines.push(`\n**Fix:** ${f.remediation}`);
    if (f.verdict) lines.push(`\n_Verdict: ${f.verdict}_`);
    lines.push("");
    lines.push("</details>");
    lines.push("");
  }

  lines.push("");
  lines.push("_Posted by AIHarness. Findings are AI-assisted; verify before acting._");
  return lines.join("\n");
}

/**
 * Post a summary of findings as an issue comment on the PR. Guarded by the
 * caller so a failure here does NOT fail the scan. `fetchImpl` is injectable
 * for tests.
 */
export async function postPrComment(
  env: Env,
  prJob: PrJob,
  findings: Finding[],
  fetchImpl: typeof fetch = fetch
): Promise<void> {
  const token = env.GITHUB_TOKEN;
  if (!token) {
    console.warn("postPrComment: GITHUB_TOKEN not set, skipping");
    return;
  }
  const body = buildCommentBody(findings, prJob.headSha);
  const res = await fetchImpl(
    `https://api.github.com/repos/${prJob.owner}/${prJob.repo}/issues/${prJob.prNumber}/comments`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "user-agent": "aiharness",
        "x-github-api-version": "2022-11-28",
      },
      body: JSON.stringify({ body }),
    } as RequestInit
  );
  if (!res.ok) {
    throw new Error(`GitHub API error posting PR comment: ${res.status}`);
  }
}
