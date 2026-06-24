import { defineConfig } from "vitest/config";

// Node-environment project for pure-logic tests that need Node-only deps (e.g. ajv,
// which is CommonJS and cannot load in the workerd pool used by the main config).
export default defineConfig({
  test: {
    name: "node",
    environment: "node",
    include: ["tests/report/sarif-schema.test.ts"],
  },
});
