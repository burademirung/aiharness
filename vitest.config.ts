import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import { configDefaults } from "vitest/config";
import path from "node:path";

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));
  return {
    test: {
      // SARIF schema validation uses ajv (CommonJS) which can't load in the workerd
      // pool — it runs in the Node project (vitest.node.config.ts) instead.
      exclude: [...configDefaults.exclude, "tests/report/sarif-schema.test.ts"],
      poolOptions: {
        workers: {
          wrangler: { configPath: "./wrangler.test.jsonc" },
          miniflare: { bindings: { TEST_MIGRATIONS: migrations } },
          // WORKAROUND: isolatedStorage and multi-worker mode trigger a miniflare
          // sqlite-shm frame-pop assertion when R2 is accessed inside
          // runInDurableObject. Consequence: D1 and R2 state is SHARED across all
          // test files in this suite. EACH TEST MUST USE UNIQUE ROW IDs — do not
          // reuse scan ids across tests, or tests will corrupt each other's state.
          isolatedStorage: false,
          singleWorker: true,
        },
      },
    },
  };
});
