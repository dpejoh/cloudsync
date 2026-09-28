/**
 * CloudSync protocol v2 key management: Argon2id KEK, random master key,
 * per-vault keys, X25519 sharing envelopes and object integrity binding.
 * The server only ever stores opaque blobs produced here.
 * Key hierarchy and threat model: docs/ARCHITECTURE.md.
 */

import { x25519 } from "@noble/curves/ed25519";
import { argon2idAsync } from "@noble/hashes/argon2";
import { base64url } from "rfc4648";

export const CRYPTO_V2_PROTOCOL = 2;
export const ACCOUNT_KDF_ALG = "argon2id";
export const ACCOUNT_KDF_PARAMS = { m: 19456, t: 2, p: 1 } as const;
export const ACCOUNT_KDF_DKLEN = 64;
export const KDF_SALT_BYTES = 16;
export const RECOVERY_SALT_BYTES = 16;
export const SYMMETRIC_KEY_BYTES = 32;
export const AES_GCM_IV_BYTES = 12;
export const X25519_KEY_BYTES = 32;
export const RECOVERY_KEY_CHARS = 24;
export const RECOVERY_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const textEncoder = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function b64uEncode(b: Uint8Array): string {
  return base64url.stringify(b, { pad: false });
}

export function b64uDecode(s: string): Uint8Array {
  return base64url.parse(s, { loose: true }) as Uint8Array;
}

export function hexEncode(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i].toString(16).padStart(2, "0");
  return out;
}

export function hexDecode(s: string): Uint8Array {
  const clean = s.trim();
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error("invalid hex string");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function generateSymmetricKey(): Uint8Array {
  return randomBytes(SYMMETRIC_KEY_BYTES);
}

/** Stable JSON serialization (sorted keys) for MACed structures. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`)
    .join(",")}}`;
}

// WebCrypto primitives

async function importAesKey(
  raw: Uint8Array,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  return await globalThis.crypto.subtle.importKey(
    "raw",
    raw as BufferSource,
    { name: "AES-GCM" },
    false,
    usage
  );
}

export async function aesGcmSeal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: string
): Promise<{ iv: Uint8Array; ct: Uint8Array }> {
  const iv = randomBytes(AES_GCM_IV_BYTES);
  const cryptoKey = await importAesKey(key, ["encrypt"]);
  const ct = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: utf8(aad) as BufferSource,
    },
    cryptoKey,
    plaintext as BufferSource
  );
  return { iv, ct: new Uint8Array(ct) };
}

export async function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ct: Uint8Array,
  aad: string
): Promise<Uint8Array> {
  const cryptoKey = await importAesKey(key, ["decrypt"]);
  const plain = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: utf8(aad) as BufferSource,
    },
    cryptoKey,
    ct as BufferSource
  );
  return new Uint8Array(plain);
}

/** Sealed format: base64url(iv || ciphertext||tag). */
export async function sealBytes(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: string
): Promise<string> {
  const { iv, ct } = await aesGcmSeal(key, plaintext, aad);
  return b64uEncode(concatBytes(iv, ct));
}

export async function openBytes(
  key: Uint8Array,
  sealed: string,
  aad: string
): Promise<Uint8Array> {
  const raw = b64uDecode(sealed);
  if (raw.length < AES_GCM_IV_BYTES + 16)
    throw new Error("sealed payload is too short");
  const iv = raw.slice(0, AES_GCM_IV_BYTES);
  const ct = raw.slice(AES_GCM_IV_BYTES);
  return await aesGcmOpen(key, iv, ct, aad);
}

export async function hmacSha256(
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await globalThis.crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    data as BufferSource
  );
  return new Uint8Array(sig);
}

async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    ikm as BufferSource,
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: utf8(info) as BufferSource,
    },
    cryptoKey,
    length * 8
  );
  return new Uint8Array(bits);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const out = await globalThis.crypto.subtle.digest(
    "SHA-256",
    data as BufferSource
  );
  return new Uint8Array(out);
}

// Account KDF (password -> KEK + auth verifier)

export interface KdfDescriptor {
  alg: typeof ACCOUNT_KDF_ALG;
  m: number;
  t: number;
  p: number;
  salt: string;
}

export function newKdfDescriptor(): KdfDescriptor {
  return {
    alg: ACCOUNT_KDF_ALG,
    m: ACCOUNT_KDF_PARAMS.m,
    t: ACCOUNT_KDF_PARAMS.t,
    p: ACCOUNT_KDF_PARAMS.p,
    salt: b64uEncode(randomBytes(KDF_SALT_BYTES)),
  };
}

/** The client pins KDF parameters; a server cannot downgrade them. */
export function assertSupportedKdf(kdf: KdfDescriptor): void {
  if (
    !kdf ||
    kdf.alg !== ACCOUNT_KDF_ALG ||
    kdf.m !== ACCOUNT_KDF_PARAMS.m ||
    kdf.t !== ACCOUNT_KDF_PARAMS.t ||
    kdf.p !== ACCOUNT_KDF_PARAMS.p ||
    !kdf.salt ||
    b64uDecode(kdf.salt).length !== KDF_SALT_BYTES
  ) {
    throw new Error("unsupported or malformed KDF parameters");
  }
}

export interface AccountKeys {
  kek: Uint8Array;
  authVerifier: string;
}

export async function deriveAccountKeys(
  password: string,
  kdf: KdfDescriptor,
  username: string
): Promise<AccountKeys> {
  assertSupportedKdf(kdf);
  const salt = b64uDecode(kdf.salt);
  const root = await argon2idAsync(utf8(password.normalize("NFKC")), salt, {
    m: kdf.m,
    t: kdf.t,
    p: kdf.p,
    dkLen: ACCOUNT_KDF_DKLEN,
  });
  const kek = await hkdfSha256(root.slice(0, 32), salt, "cloudsync:kek:v2", 32);
  const authKey = await hkdfSha256(
    root.slice(32, 64),
    salt,
    "cloudsync:auth:v2",
    32
  );
  const authVerifier = hexEncode(
    await hmacSha256(
      authKey,
      utf8(`cloudsync-verifier:v2:${username.trim().toLowerCase()}`)
    )
  );
  return { kek, authVerifier };
}

// Recovery key

export function generateRecoveryKey(): string {
  const bytes = randomBytes(RECOVERY_KEY_CHARS);
  let body = "";
  for (let i = 0; i < RECOVERY_KEY_CHARS; i++) {
    body += RECOVERY_KEY_ALPHABET[bytes[i] % RECOVERY_KEY_ALPHABET.length];
  }
  const groups = body.match(/.{1,4}/g) ?? [];
  return `SYNC-${groups.join("-")}`;
}

export function normalizeRecoveryKey(key: string): string {
  return key
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
}

export function newRecoverySalt(): string {
  return b64uEncode(randomBytes(RECOVERY_SALT_BYTES));
}

export async function deriveRecoveryKek(
  recoveryKey: string,
  saltB64: string
): Promise<Uint8Array> {
  const ikm = utf8(normalizeRecoveryKey(recoveryKey));
  if (ikm.length < 16) throw new Error("recovery key is too short");
  return await hkdfSha256(
    ikm,
    b64uDecode(saltB64),
    "cloudsync:recovery-kek:v2",
    32
  );
}

// Identity keypair

export interface IdentityKeyPair {
  publicKey: string;
  privateKey: Uint8Array;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey: b64uEncode(publicKey), privateKey };
}

export async function sealIdentityPrivateKey(
  mk: Uint8Array,
  privateKey: Uint8Array
): Promise<string> {
  return await sealBytes(mk, privateKey, "cloudsync:identity-private:v2");
}

export async function openIdentityPrivateKey(
  mk: Uint8Array,
  sealed: string
): Promise<Uint8Array> {
  return await openBytes(mk, sealed, "cloudsync:identity-private:v2");
}

export async function identityFingerprint(
  publicKeyB64: string
): Promise<string> {
  const digest = await sha256(b64uDecode(publicKeyB64));
  const groups = hexEncode(digest.slice(0, 8)).match(/.{4}/g) ?? [];
  return groups.join("-").toUpperCase();
}

// Master key / vault key wraps

const MASTER_KEY_AAD = "cloudsync:master-key:v2";

export async function wrapMasterKey(
  kek: Uint8Array,
  mk: Uint8Array
): Promise<string> {
  return await sealBytes(kek, mk, MASTER_KEY_AAD);
}

export async function unwrapMasterKey(
  kek: Uint8Array,
  wrapped: string
): Promise<Uint8Array> {
  return await openBytes(kek, wrapped, MASTER_KEY_AAD);
}

export function vaultKeyAad(vaultId: string, version: number): string {
  return `cloudsync:vault-key:v2:${vaultId}:${version}`;
}

export async function wrapVaultKey(
  mk: Uint8Array,
  vaultId: string,
  version: number,
  vk: Uint8Array
): Promise<string> {
  return await sealBytes(mk, vk, vaultKeyAad(vaultId, version));
}

export async function unwrapVaultKey(
  mk: Uint8Array,
  vaultId: string,
  version: number,
  wrapped: string
): Promise<Uint8Array> {
  return await openBytes(mk, wrapped, vaultKeyAad(vaultId, version));
}

/** rclone takes a password string; vault keys are represented in hex. */
export function vaultKeyToPassword(vk: Uint8Array): string {
  return hexEncode(vk);
}

/**
 * Deterministic key for a vault rotation. Deriving it from the master key
 * (not random per attempt) makes an interrupted re-key safely retryable:
 * re-running produces the same key, so uploads are idempotent.
 */
export async function deriveVaultRotationKey(
  masterKey: Uint8Array,
  vaultId: string,
  version: number
): Promise<Uint8Array> {
  return await hkdfSha256(
    masterKey,
    new Uint8Array(0),
    `cloudsync:rotation:v2:${vaultId}:${version}`,
    32
  );
}

// Vault key envelopes (X25519 + HKDF + AES-GCM)

export interface KeyMaterialVaultEntry {
  version: number;
  wrappedKey: string;
}

export interface VaultKeyEnvelope {
  v: number;
  vaultId: string;
  keyVersion: number;
  ownerId: string;
  recipientId: string;
  sender: string;
  sealed: string;
}

export function envelopeContext(
  e: Omit<VaultKeyEnvelope, "sender" | "sealed">
): string {
  return [
    `cloudsync:envelope:v${CRYPTO_V2_PROTOCOL}`,
    `vault=${e.vaultId}`,
    `version=${e.keyVersion}`,
    `owner=${e.ownerId}`,
    `recipient=${e.recipientId}`,
  ].join("|");
}

export async function sealVaultKeyForRecipient(
  vk: Uint8Array,
  recipientPublicKeyB64: string,
  ctx: Omit<VaultKeyEnvelope, "sender" | "sealed">
): Promise<VaultKeyEnvelope> {
  const recipientPublic = b64uDecode(recipientPublicKeyB64);
  if (recipientPublic.length !== X25519_KEY_BYTES)
    throw new Error("invalid recipient public key");
  const ephemeralPrivate = x25519.utils.randomPrivateKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const shared = x25519.getSharedSecret(ephemeralPrivate, recipientPublic);
  const context = envelopeContext(ctx);
  const wrapKey = await hkdfSha256(shared, new Uint8Array(0), context, 32);
  const sealed = await sealBytes(wrapKey, vk, context);
  return { ...ctx, sender: b64uEncode(ephemeralPublic), sealed };
}

export async function openVaultKeyEnvelope(
  envelope: VaultKeyEnvelope,
  recipientPrivateKey: Uint8Array
): Promise<Uint8Array> {
  if (envelope.v !== CRYPTO_V2_PROTOCOL)
    throw new Error("unsupported envelope version");
  const senderPublic = b64uDecode(envelope.sender);
  if (senderPublic.length !== X25519_KEY_BYTES)
    throw new Error("invalid envelope sender key");
  const shared = x25519.getSharedSecret(recipientPrivateKey, senderPublic);
  const context = envelopeContext({
    v: envelope.v,
    vaultId: envelope.vaultId,
    keyVersion: envelope.keyVersion,
    ownerId: envelope.ownerId,
    recipientId: envelope.recipientId,
  });
  const wrapKey = await hkdfSha256(shared, new Uint8Array(0), context, 32);
  return await openBytes(wrapKey, envelope.sealed, context);
}

// Key material document (server-stored, opaque to the server)

export interface AccountKeyMaterial {
  v: number;
  accountId: string;
  username: string;
  kdf: KdfDescriptor;
  recovery: { salt: string } | null;
  wrappedMasterKey: string;
  wrappedMasterKeyRecovery: string | null;
  identity: { publicKey: string; sealedPrivateKey: string };
  vaults: Record<string, KeyMaterialVaultEntry>;
  rev: number;
  mac: string;
}

const KEY_MATERIAL_MAC_AAD = "cloudsync:key-material:v2";

export function keyMaterialPayload(km: AccountKeyMaterial): string {
  const { mac: _mac, ...rest } = km;
  return canonicalJson(rest);
}

export async function macKeyMaterial(
  km: AccountKeyMaterial,
  kek: Uint8Array
): Promise<string> {
  return hexEncode(
    await hmacSha256(
      kek,
      utf8(`${KEY_MATERIAL_MAC_AAD}:${keyMaterialPayload(km)}`)
    )
  );
}

export async function verifyKeyMaterialMac(
  km: AccountKeyMaterial,
  kek: Uint8Array
): Promise<boolean> {
  const expected = await macKeyMaterial(km, kek);
  return constantTimeEqual(hexDecode(expected), hexDecode(km.mac));
}

export interface CreateKeyMaterialResult {
  keyMaterial: AccountKeyMaterial;
  kek: Uint8Array;
  masterKey: Uint8Array;
  identity: IdentityKeyPair;
  authVerifier: string;
}

export async function createKeyMaterialWithKek(opts: {
  accountId: string;
  username: string;
  kek: Uint8Array;
  kdf: KdfDescriptor;
  recoveryKey?: string;
}): Promise<{
  keyMaterial: AccountKeyMaterial;
  masterKey: Uint8Array;
  identity: IdentityKeyPair;
}> {
  const masterKey = generateSymmetricKey();
  const identity = generateIdentityKeyPair();

  const wrappedMasterKey = await wrapMasterKey(opts.kek, masterKey);
  let wrappedMasterKeyRecovery: string | null = null;
  let recovery: { salt: string } | null = null;
  if (opts.recoveryKey) {
    recovery = { salt: newRecoverySalt() };
    const recoveryKek = await deriveRecoveryKek(
      opts.recoveryKey,
      recovery.salt
    );
    wrappedMasterKeyRecovery = await wrapMasterKey(recoveryKek, masterKey);
  }

  const km: AccountKeyMaterial = {
    v: CRYPTO_V2_PROTOCOL,
    accountId: opts.accountId,
    username: opts.username,
    kdf: opts.kdf,
    recovery,
    wrappedMasterKey,
    wrappedMasterKeyRecovery,
    identity: {
      publicKey: identity.publicKey,
      sealedPrivateKey: await sealIdentityPrivateKey(
        masterKey,
        identity.privateKey
      ),
    },
    vaults: {},
    rev: 1,
    mac: "",
  };
  km.mac = await macKeyMaterial(km, opts.kek);
  return { keyMaterial: km, masterKey, identity };
}

export async function createAccountKeyMaterial(opts: {
  accountId: string;
  username: string;
  password: string;
  recoveryKey?: string;
}): Promise<CreateKeyMaterialResult> {
  const kdf = newKdfDescriptor();
  const { kek, authVerifier } = await deriveAccountKeys(
    opts.password,
    kdf,
    opts.username
  );
  const created = await createKeyMaterialWithKek({
    accountId: opts.accountId,
    username: opts.username,
    kek,
    kdf,
    recoveryKey: opts.recoveryKey,
  });
  return { ...created, kek, authVerifier };
}

export async function unlockKeyMaterial(
  km: AccountKeyMaterial,
  kek: Uint8Array
): Promise<{ masterKey: Uint8Array; identityPrivateKey: Uint8Array }> {
  if (km.v !== CRYPTO_V2_PROTOCOL)
    throw new Error("unsupported key material version");
  if (!(await verifyKeyMaterialMac(km, kek)))
    throw new Error("key material failed integrity check");
  const masterKey = await unwrapMasterKey(kek, km.wrappedMasterKey);
  const identityPrivateKey = await openIdentityPrivateKey(
    masterKey,
    km.identity.sealedPrivateKey
  );
  return { masterKey, identityPrivateKey };
}

export async function unlockKeyMaterialWithRecovery(
  km: AccountKeyMaterial,
  recoveryKey: string
): Promise<{ masterKey: Uint8Array; identityPrivateKey: Uint8Array }> {
  if (!km.recovery || !km.wrappedMasterKeyRecovery) {
    throw new Error("this account has no recovery key configured");
  }
  const recoveryKek = await deriveRecoveryKek(recoveryKey, km.recovery.salt);
  const masterKey = await unwrapMasterKey(
    recoveryKek,
    km.wrappedMasterKeyRecovery
  );
  const identityPrivateKey = await openIdentityPrivateKey(
    masterKey,
    km.identity.sealedPrivateKey
  );
  return { masterKey, identityPrivateKey };
}

/** Re-wraps the master key under a new KEK (password change / recovery). */
export async function rewrapKeyMaterial(
  km: AccountKeyMaterial,
  oldKek: Uint8Array,
  newKek: Uint8Array,
  newKdf?: KdfDescriptor
): Promise<AccountKeyMaterial> {
  const masterKey = await unwrapMasterKey(oldKek, km.wrappedMasterKey);
  const wrappedMasterKey = await wrapMasterKey(newKek, masterKey);
  const next: AccountKeyMaterial = {
    ...km,
    kdf: newKdf ?? km.kdf,
    wrappedMasterKey,
    rev: km.rev + 1,
    mac: "",
  };
  next.mac = await macKeyMaterial(next, newKek);
  return next;
}

/**
 * Re-wraps the master key using the recovery key instead of the password KEK.
 * Used after a recovery-key reset to attach the new password.
 */
export async function rewrapKeyMaterialFromRecovery(
  km: AccountKeyMaterial,
  recoveryKey: string,
  newKek: Uint8Array,
  newRecoverySalt?: string,
  newKdf?: KdfDescriptor
): Promise<AccountKeyMaterial> {
  const { masterKey } = await unlockKeyMaterialWithRecovery(km, recoveryKey);
  const wrappedMasterKey = await wrapMasterKey(newKek, masterKey);
  const recovery = newRecoverySalt ? { salt: newRecoverySalt } : km.recovery;
  const wrappedMasterKeyRecovery =
    newRecoverySalt !== undefined
      ? await wrapMasterKey(
          await deriveRecoveryKek(recoveryKey, newRecoverySalt),
          masterKey
        )
      : km.wrappedMasterKeyRecovery;
  const next: AccountKeyMaterial = {
    ...km,
    kdf: newKdf ?? km.kdf,
    recovery,
    wrappedMasterKeyRecovery,
    wrappedMasterKey,
    rev: km.rev + 1,
    mac: "",
  };
  next.mac = await macKeyMaterial(next, newKek);
  return next;
}

export async function withVaultKey(
  km: AccountKeyMaterial,
  kek: Uint8Array,
  vaultId: string,
  version: number,
  vk: Uint8Array
): Promise<AccountKeyMaterial> {
  const mk = await unwrapMasterKey(kek, km.wrappedMasterKey);
  const wrappedKey = await wrapVaultKey(mk, vaultId, version, vk);
  const vaults: Record<string, KeyMaterialVaultEntry> = {
    ...km.vaults,
    [vaultId]: { version, wrappedKey },
  };
  const next: AccountKeyMaterial = { ...km, vaults, rev: km.rev + 1, mac: "" };
  next.mac = await macKeyMaterial(next, kek);
  return next;
}

export async function withoutVaultKey(
  km: AccountKeyMaterial,
  kek: Uint8Array,
  vaultId: string
): Promise<AccountKeyMaterial> {
  const vaults = { ...km.vaults };
  delete vaults[vaultId];
  const next: AccountKeyMaterial = { ...km, vaults, rev: km.rev + 1, mac: "" };
  next.mac = await macKeyMaterial(next, kek);
  return next;
}

export async function getVaultKey(
  km: AccountKeyMaterial,
  masterKey: Uint8Array,
  vaultId: string
): Promise<{ version: number; vk: Uint8Array } | null> {
  const entry = km.vaults[vaultId];
  if (!entry) return null;
  const vk = await unwrapVaultKey(
    masterKey,
    vaultId,
    entry.version,
    entry.wrappedKey
  );
  return { version: entry.version, vk };
}

// Object integrity binding (name <-> content)

export async function deriveIntegrityKey(vk: Uint8Array): Promise<Uint8Array> {
  return await hkdfSha256(vk, new Uint8Array(0), "cloudsync:integrity:v2", 32);
}

export async function computeIntegrityMac(
  integrityKey: Uint8Array,
  keyRaw: string,
  content: Uint8Array
): Promise<string> {
  const digest = await sha256(content);
  return hexEncode(
    await hmacSha256(
      integrityKey,
      concatBytes(utf8(keyRaw), new Uint8Array([0]), digest)
    )
  );
}

export async function verifyIntegrityMac(
  integrityKey: Uint8Array,
  keyRaw: string,
  content: Uint8Array,
  mac: string
): Promise<boolean> {
  const expected = await computeIntegrityMac(integrityKey, keyRaw, content);
  return constantTimeEqual(hexDecode(expected), hexDecode(mac));
}
