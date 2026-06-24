import { env, runInDurableObject, applyD1Migrations } from "cloudflare:test";
import { beforeAll, describe, it, expect } from "vitest";
import semgrep from "../../fixtures/semgrep-output.json";

beforeAll(async () => {
  // @ts-expect-error test migrations binding
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
});

describe("ScanRunner state machine", () => {
  it("normalizes container output into persisted findings", async () => {
    const id = env.SCAN_RUNNER.idFromName("t1");
    const stub = env.SCAN_RUNNER.get(id);
    await runInDurableObject(stub, async (instance: any) => {
      // inject a fake container scan so we don't boot a real container in tests
      instance.scanFn = async () => semgrep;
      const findings = await instance.scanToFindings("python", []);
      expect(findings).toHaveLength(1);
      expect(findings[0].cwe).toBe("CWE-78");
    });
  });
});
