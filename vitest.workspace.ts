// Two test projects: the Workers pool (workerd) for everything that touches
// Cloudflare bindings, and a Node project for pure-logic tests that need Node-only
// CommonJS deps (the SARIF schema validation uses ajv).
export default ["./vitest.config.ts", "./vitest.node.config.ts"];
