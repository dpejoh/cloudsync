function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

async function pbkdf2Derive(
  password: string,
  saltStr: string,
  iterations = 100000
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const salt = enc.encode(saltStr);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return bufferToHex(derivedBits);
}

export interface DerivedCredentials {
  authVerifier: string;
  encryptionKey: string;
}

export async function deriveZeroKnowledgeKeys(
  account: string,
  password: string
): Promise<DerivedCredentials> {
  const normalized = (account || "default").trim().toLowerCase();
  const authVerifier = await pbkdf2Derive(password, `cloudsync-auth:${normalized}`);
  const encryptionKey = await pbkdf2Derive(password, `cloudsync-e2ee:${normalized}`);

  return { authVerifier, encryptionKey };
}

export async function deriveRecoveryVerifier(recoveryKey: string): Promise<string> {
  const cleanKey = recoveryKey.trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(`cloudsync-recovery:${cleanKey}`));
  return bufferToHex(hash);
}

export function generateRecoveryKey(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let code = "SYNC";
  for (let i = 0; i < 16; i++) {
    if (i % 4 === 0) code += "-";
    code += chars[bytes[i] % chars.length];
  }
  return code;
}

export function generateTotpSecret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  let secret = "";
  for (let i = 0; i < 20; i++) {
    secret += alphabet[bytes[i] % alphabet.length];
  }
  return secret;
}
