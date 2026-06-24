import { describe, it, expect } from "vitest";
import { encryptKey, decryptKey } from "../../src/crypto/envelope";

const KEK = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

describe("envelope encryption", () => {
  it("round-trips a secret", async () => {
    const secret = "sk-ant-test-key-123";
    const env = await encryptKey(KEK, secret);
    expect(env).not.toContain(secret);
    expect(await decryptKey(KEK, env)).toBe(secret);
  });

  it("fails to decrypt with the wrong KEK", async () => {
    const env = await encryptKey(KEK, "secret");
    const wrong = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    await expect(decryptKey(wrong, env)).rejects.toThrow();
  });
});
