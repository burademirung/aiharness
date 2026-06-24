import { env, applyD1Migrations } from "cloudflare:test";
import { beforeAll, describe, it, expect } from "vitest";
import { createScan, getScan, setScanStatus, storeJobKey, getJobKey, deleteJobKey, insertFindings, getFindings, storePrJob, getPrJob } from "../../src/db/queries";

beforeAll(async () => {
  // @ts-expect-error provided by vitest-pool-workers test bindings
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});

describe("db queries", () => {
  it("creates and reads a scan, updates status", async () => {
    await createScan(env.DB, {
      id: "s1", language: "python", status: "queued",
      sourceKey: "src/s1.tar", modelId: "claude", modelVersion: "claude-opus-4-8",
    });
    let scan = await getScan(env.DB, "s1");
    expect(scan?.status).toBe("queued");
    await setScanStatus(env.DB, "s1", "scanning");
    scan = await getScan(env.DB, "s1");
    expect(scan?.status).toBe("scanning");
  });

  it("stores, reads, and deletes a job key", async () => {
    await createScan(env.DB, {
      id: "s2", language: "python", status: "queued",
      sourceKey: "src/s2.tar", modelId: "claude", modelVersion: "claude-opus-4-8",
    });
    await storeJobKey(env.DB, "s2", "CIPHERTEXT");
    expect(await getJobKey(env.DB, "s2")).toBe("CIPHERTEXT");
    await deleteJobKey(env.DB, "s2");
    expect(await getJobKey(env.DB, "s2")).toBeNull();
  });

  it("inserts and reads findings with snippet, explanation, and remediation", async () => {
    await createScan(env.DB, {
      id: "s3", language: "python", status: "queued",
      sourceKey: "src/s3.tar", modelId: "claude", modelVersion: "claude-opus-4-8",
    });
    const finding = {
      id: "f1",
      ruleId: "test-rule",
      cwe: "CWE-89",
      severity: "high" as const,
      message: "SQL injection detected",
      file: "app.py",
      startLine: 10,
      endLine: 15,
      snippet: "query = f\"SELECT * FROM users WHERE id = {id}\"",
      explanation: "User input is directly interpolated into SQL query",
      remediation: "Use parameterized queries instead of string interpolation",
    };
    await insertFindings(env.DB, "s3", [finding]);
    const findings = await getFindings(env.DB, "s3");
    expect(findings).toHaveLength(1);
    expect(findings[0].snippet).toBe("query = f\"SELECT * FROM users WHERE id = {id}\"");
    expect(findings[0].explanation).toBe("User input is directly interpolated into SQL query");
    expect(findings[0].remediation).toBe("Use parameterized queries instead of string interpolation");
  });

  it("stores and reads a pr_job (round-trip)", async () => {
    await createScan(env.DB, {
      id: "s4", language: "python", status: "queued",
      sourceKey: "src/s4.tar", modelId: "claude", modelVersion: "claude-opus-4-8",
    });
    expect(await getPrJob(env.DB, "s4")).toBeNull();
    await storePrJob(env.DB, {
      scanId: "s4", owner: "acme", repo: "widgets", prNumber: 42, headSha: "deadbeef",
    });
    const job = await getPrJob(env.DB, "s4");
    expect(job).toEqual({
      scanId: "s4", owner: "acme", repo: "widgets", prNumber: 42, headSha: "deadbeef",
    });
  });
});
