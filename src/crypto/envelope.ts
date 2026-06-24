const enc = new TextEncoder();
const dec = new TextDecoder();

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

async function importKek(kekB64: string): Promise<CryptoKey> {
  // KEK is only ever used to wrap/unwrap the per-job DEK — least privilege.
  return crypto.subtle.importKey("raw", b64ToBytes(kekB64), { name: "AES-GCM" }, false, ["wrapKey", "unwrapKey"]);
}

// Envelope format: base64(dekIv) + "." + base64(wrappedDek) + "." + base64(dataIv) + "." + base64(ciphertext)
export async function encryptKey(kekB64: string, plaintext: string): Promise<string> {
  const kek = await importKek(kekB64);
  // AES-GCM with a length always yields a single CryptoKey (never a CryptoKeyPair);
  // the cast narrows the union for wrapKey/encrypt below.
  const dek = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
  const dekIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedDek = new Uint8Array(await crypto.subtle.wrapKey("raw", dek, kek, { name: "AES-GCM", iv: dekIv }));
  const dataIv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: dataIv }, dek, enc.encode(plaintext)));
  // pack dekIv + dataIv together so unwrap can recover
  return [bytesToB64(dekIv), bytesToB64(wrappedDek), bytesToB64(dataIv), bytesToB64(ciphertext)].join(".");
}

export async function decryptKey(kekB64: string, envelope: string): Promise<string> {
  const kek = await importKek(kekB64);
  const parts = envelope.split(".");
  if (parts.length !== 4) throw new Error("malformed envelope");
  const [dekIvB64, wrappedDekB64, dataIvB64, ciphertextB64] = parts as [string, string, string, string];
  const dek = await crypto.subtle.unwrapKey(
    "raw", b64ToBytes(wrappedDekB64), kek, { name: "AES-GCM", iv: b64ToBytes(dekIvB64) },
    { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(dataIvB64) }, dek, b64ToBytes(ciphertextB64));
  return dec.decode(plain);
}
