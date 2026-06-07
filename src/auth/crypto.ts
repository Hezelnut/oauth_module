/**
 * AES-GCM 256bit 암호화 유틸리티
 * Web Crypto API 사용 (Node.js 18+ / Cloudflare Workers 모두 호환)
 */

export async function encrypt(
  plaintext: string,
  hexKey: string
): Promise<{ iv: string; ciphertext: string }> {
  const key = await importKey(hexKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  return {
    iv: uint8ToBase64(iv),
    ciphertext: uint8ToBase64(new Uint8Array(encrypted)),
  };
}

export async function decrypt(
  iv: string,
  ciphertext: string,
  hexKey: string
): Promise<string> {
  const key = await importKey(hexKey);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToUint8(iv) },
    key,
    base64ToUint8(ciphertext)
  );
  return new TextDecoder().decode(decrypted);
}

async function importKey(hexKey: string): Promise<CryptoKey> {
  const bytes = hexToUint8(hexKey);
  if (bytes.length !== 32) throw new AuthCryptoError("Encryption key must be 32 bytes (64 hex chars)");
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function hexToUint8(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return result;
}

function uint8ToBase64(buf: Uint8Array): string {
  return btoa(String.fromCharCode(...buf));
}

function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export class AuthCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthCryptoError";
  }
}
