import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  CLOUDSYNC_BUCKET: R2Bucket;
  CLOUDSYNC_KV?: KVNamespace;
  JWT_SECRET?: string;
  WORKER_MODE?: string; // "single" | "multi"
  SINGLE_USER_PASSWORD?: string;
  TRUST_PROXY?: string; // "1"/"true" to trust X-Forwarded-For for rate limiting
};

type Variables = {
  userId: string;
  username: string;
};

interface VaultChange {
  rev: number;
  key: string;
  action: "put" | "delete" | "cursor";
  mtime: number;
  size?: number;
  cursor?: { line: number; ch: number };
  deviceId?: string;
  deviceName?: string;
}

interface CachedCursor {
  key: string;
  cursor: { line: number; ch: number };
  deviceId: string;
  deviceName: string;
  rev: number;
  timestamp: number;
}

interface DeviceInfo {
  deviceId: string;
  deviceName: string;
  platform: "desktop" | "mobile" | "unknown";
  lastActive: number;
  lastBackup?: number;
  fileCount?: number;
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// In-memory caches for multi-device cursor updates and storage calculations
// vaultKey -> Map<deviceId, CachedCursor>
const CURSOR_TTL_MS = 30000; // 30-second TTL for active cursor presence
const cursorCache = new Map<string, Map<string, CachedCursor>>();
const storageCache = new Map<string, { bytes: number; timestamp: number }>();

app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "no-referrer");
});

app.onError((err, c) => {
  console.error("Worker unhandled error:", err);
  return c.json({ error: "Internal server error" }, 500);
});

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: [
      "Authorization",
      "Content-Type",
      "x-mtime",
      "x-ctime",
      "x-vault-id",
      "x-cursor-line",
      "x-cursor-ch",
      "x-device-id",
      "x-device-name",
      "x-integrity",
      "x-rotation",
      "x-purge",
      "x-key-version",
    ],
    exposeHeaders: [
      "Content-Length",
      "x-mtime",
      "x-ctime",
      "x-cursor-line",
      "x-cursor-ch",
      "x-device-id",
      "x-device-name",
      "x-integrity",
      "ETag",
    ],
  })
);

// Helpers
function getJwtSecret(c: any): string {
  const secret = c.env.JWT_SECRET;
  if (!secret || typeof secret !== "string" || secret.length < 16) {
    throw new Error(
      "JWT_SECRET is not configured or is too short. Set it with `wrangler secret put JWT_SECRET` (or the JWT_SECRET env var on VPS)."
    );
  }
  return secret;
}

function checkAuthRateLimitKey(c: any): string {
  const cf = c.req.header("cf-connecting-ip");
  if (cf) return cf;
  const trustProxy = c.env.TRUST_PROXY === "1" || c.env.TRUST_PROXY === "true";
  if (!trustProxy) return "direct";
  return (
    c.req.header("x-real-ip") || c.req.header("x-forwarded-for") || "direct"
  );
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]);
  return base64UrlEncode(binary);
}

function base64UrlDecode(str: string): string {
  let normalized = str.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4) normalized += "=";
  return atob(normalized);
}

function base32Decode(str: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = str.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean[i]);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function signJwt(
  payload: Record<string, any>,
  secret: string
): Promise<string> {
  const enc = new TextEncoder();
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const data = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return `${data}.${base64UrlEncodeBytes(new Uint8Array(sig))}`;
}

async function verifyJwt(
  token: string,
  secret: string
): Promise<Record<string, any> | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, sigB64] = parts;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const sigStr = base64UrlDecode(sigB64);
    const sigBytes = new Uint8Array(sigStr.length);
    for (let i = 0; i < sigStr.length; i++) sigBytes[i] = sigStr.charCodeAt(i);

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      enc.encode(`${headerB64}.${payloadB64}`)
    );
    if (!valid) return null;

    const payload = JSON.parse(base64UrlDecode(payloadB64));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;

    return payload;
  } catch {
    return null;
  }
}

async function hashVerifier(verifier: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(verifier.toLowerCase())
  );
  const bytes = new Uint8Array(sig);
  let hex = "";
  for (let i = 0; i < bytes.length; i++)
    hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

/**
 * Mirrors the plugin's PBKDF2 derivation (authHelper.ts) so single-user mode can
 * validate a password supplied via the SINGLE_USER_PASSWORD env var.
 */
async function deriveAuthVerifier(
  password: string,
  account: string
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(`cloudsync-auth:${account}`),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );
  const bytes = new Uint8Array(bits);
  let hex = "";
  for (let i = 0; i < bytes.length; i++)
    hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

async function verifyTotpCode(
  secretBase32: string,
  code: string
): Promise<boolean> {
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  const cleanCode = code.trim();
  const keyBytes = base32Decode(secretBase32);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  for (let offset = -1; offset <= 1; offset++) {
    const step = currentStep + offset;
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(step / 0x100000000));
    view.setUint32(4, step >>> 0);

    const sig = await crypto.subtle.sign("HMAC", cryptoKey, buf);
    const hash = new Uint8Array(sig);
    const idx = hash[hash.length - 1] & 0x0f;
    const binary =
      ((hash[idx] & 0x7f) << 24) |
      ((hash[idx + 1] & 0xff) << 16) |
      ((hash[idx + 2] & 0xff) << 8) |
      (hash[idx + 3] & 0xff);

    const expected = (binary % 1000000).toString().padStart(6, "0");
    if (expected === cleanCode) return true;
  }
  return false;
}

function isValidUsername(s: string): boolean {
  return typeof s === "string" && /^[a-zA-Z0-9_-]{3,32}$/.test(s);
}

function isValidHexHash(s: string): boolean {
  return typeof s === "string" && /^[a-fA-F0-9]{64}$/.test(s);
}

function isValidTotpSecret(s: string): boolean {
  return typeof s === "string" && /^[A-Z2-7]{16,64}$/.test(s);
}

function isValidTotpCode(s: string): boolean {
  return typeof s === "string" && /^\d{6}$/.test(s);
}

function isValidVaultName(s: string): boolean {
  return typeof s === "string" && /^[a-zA-Z0-9._-]{1,64}$/.test(s);
}

function isValidFileKey(key: string): boolean {
  if (!key || typeof key !== "string" || key.length > 1024) return false;
  if (key.startsWith("/") || key.includes("\\")) return false;
  if (/(^|[/\\])\.\.([/\\]|$)/.test(key)) return false;
  // Reserved internal objects (metadata, change feed, vault marker) must never be
  // writable through the user-facing sync API.
  if (key.split("/").some((segment) => segment.startsWith(".cloudsync")))
    return false;
  return true;
}

function toStorageKey(key: string): string {
  return `_system_store/${key.replace(/[^a-zA-Z0-9._-]/g, "_")}.json`;
}

async function getStoredData(c: any, key: string): Promise<string | null> {
  if (c.env.CLOUDSYNC_KV) {
    try {
      const val = await c.env.CLOUDSYNC_KV.get(key);
      if (val !== null && val !== undefined) return val;
    } catch (e) {
      console.warn("KV get failed, falling back to bucket:", e);
    }
  }
  if (c.env.CLOUDSYNC_BUCKET) {
    try {
      const obj = await c.env.CLOUDSYNC_BUCKET.get(toStorageKey(key));
      if (obj) {
        return await obj.text();
      }
    } catch (e) {
      console.warn("Bucket get failed for system key:", e);
    }
  }
  return null;
}

async function putStoredData(
  c: any,
  key: string,
  value: string
): Promise<void> {
  if (c.env.CLOUDSYNC_BUCKET) {
    try {
      await c.env.CLOUDSYNC_BUCKET.put(toStorageKey(key), value, {
        httpMetadata: { contentType: "application/json" },
      });
    } catch (e) {
      console.error("Bucket put failed for system key:", e);
    }
  }
  if (c.env.CLOUDSYNC_KV) {
    try {
      await c.env.CLOUDSYNC_KV.put(key, value);
    } catch (e) {
      console.warn(
        "KV put quota limit exceeded, securely using R2 storage:",
        e
      );
    }
  }
}

async function deleteStoredData(c: any, key: string): Promise<void> {
  if (c.env.CLOUDSYNC_BUCKET) {
    try {
      await c.env.CLOUDSYNC_BUCKET.delete(toStorageKey(key));
    } catch {}
  }
  if (c.env.CLOUDSYNC_KV) {
    try {
      await c.env.CLOUDSYNC_KV.delete(key);
    } catch {}
  }
}

let lastAssignedRev = 0;
function getNextRevision(): number {
  const now = Date.now();
  lastAssignedRev = now > lastAssignedRev ? now : lastAssignedRev + 1;
  return lastAssignedRev;
}

const authRateLimitMap = new Map<
  string,
  { count: number; resetTime: number }
>();
function checkAuthRateLimit(
  clientIp: string,
  limit = 20,
  windowMs = 60_000
): boolean {
  const now = Date.now();
  const record = authRateLimitMap.get(clientIp);
  if (!record || now > record.resetTime) {
    authRateLimitMap.set(clientIp, { count: 1, resetTime: now + windowMs });
    return true;
  }
  if (record.count >= limit) return false;
  record.count += 1;
  return true;
}

function detectSafeImageType(
  bytes: Uint8Array
): { mime: string; ext: string } | null {
  if (bytes.length < 12) return null;

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return { mime: "image/png", ext: "png" };
  }

  // JPEG: FF D8 FF
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return { mime: "image/jpeg", ext: "jpg" };
  }

  // WebP: 'RIFF' .... 'WEBP'
  if (
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return { mime: "image/webp", ext: "webp" };
  }

  // GIF: GIF87a or GIF89a
  if (
    bytes[0] === 0x47 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x38 &&
    (bytes[4] === 0x37 || bytes[4] === 0x39) &&
    bytes[5] === 0x61
  ) {
    return { mime: "image/gif", ext: "gif" };
  }

  return null;
}

// Per-vault serialization for metadata read-modify-write operations inside one
// isolate; cross-isolate safety relies on the conditional (etag) put below.
const vaultLocks = new Map<string, Promise<unknown>>();
function withVaultLock<T>(vaultKey: string, fn: () => Promise<T>): Promise<T> {
  const prev = vaultLocks.get(vaultKey) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const guarded = run.catch(() => {});
  vaultLocks.set(vaultKey, guarded);
  guarded.finally(() => {
    if (vaultLocks.get(vaultKey) === guarded) {
      vaultLocks.delete(vaultKey);
    }
  });
  return run;
}

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB per object
const USER_QUOTA_BYTES = 10 * 1024 * 1024 * 1024; // advertised 10 GB quota, now enforced
const HISTORY_MAX_BYTES = 2 * 1024 * 1024;
const HISTORY_MAX_VERSIONS = 50;

function decodeDeviceName(raw?: string | null): string | undefined {
  if (!raw) return undefined;
  try {
    return decodeURIComponent(raw).slice(0, 64);
  } catch {
    return undefined;
  }
}

function isValidDeviceId(s: string | undefined): boolean {
  return !s || /^[a-zA-Z0-9._-]{1,64}$/.test(s);
}

async function getUserStorageBytes(c: any, userId: string): Promise<number> {
  const cached = storageCache.get(userId);
  if (cached && Date.now() - cached.timestamp < 300_000) {
    return cached.bytes;
  }
  let total = 0;
  let cursor: string | undefined = undefined;
  let truncated = true;
  while (truncated) {
    const list: any = await c.env.CLOUDSYNC_BUCKET.list({
      prefix: `users/${userId}/`,
      cursor,
      limit: 1000,
    });
    for (const obj of list.objects) total += obj.size;
    truncated = list.truncated;
    cursor = list.truncated ? list.cursor : undefined;
  }
  storageCache.set(userId, { bytes: total, timestamp: Date.now() });
  return total;
}

/**
 * Saves the current version of an object into history before it is overwritten.
 * Works for every object (encrypted filenames have no extension to inspect).
 */
async function snapshotExisting(
  c: any,
  ownerId: string,
  vault: string,
  key: string,
  existing: any
): Promise<void> {
  if (!existing || existing.size <= 0 || existing.size > HISTORY_MAX_BYTES)
    return;
  const existingMtime = existing.customMetadata?.mtime || `${Date.now()}`;
  const prefix = `users/${ownerId}/history/${vault}/${key}/`;
  const historyMetadata: Record<string, string> = {
    mtime: existingMtime,
    size: `${existing.size}`,
  };
  if (existing.customMetadata?.integrity) {
    historyMetadata.integrity = existing.customMetadata.integrity;
  }
  await c.env.CLOUDSYNC_BUCKET.put(
    `${prefix}${existingMtime}`,
    await existing.arrayBuffer(),
    {
      customMetadata: historyMetadata,
    }
  );
  try {
    const list: any = await c.env.CLOUDSYNC_BUCKET.list({
      prefix,
      limit: 1000,
    });
    if (list.objects.length > HISTORY_MAX_VERSIONS) {
      const sorted = [...list.objects].sort((a, b) =>
        a.key.localeCompare(b.key)
      );
      const toDelete = sorted
        .slice(0, sorted.length - HISTORY_MAX_VERSIONS)
        .map((o) => o.key);
      if (toDelete.length > 0) await c.env.CLOUDSYNC_BUCKET.delete(toDelete);
    }
  } catch {}
}

const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

async function cleanupTrash(
  c: any,
  ownerId: string,
  vault: string
): Promise<void> {
  try {
    const prefix = `users/${ownerId}/trash/${vault}/`;
    const list: any = await c.env.CLOUDSYNC_BUCKET.list({
      prefix,
      limit: 1000,
    });
    const now = Date.now();
    const expired = list.objects
      .filter((o: any) => {
        const deletedAt = o.customMetadata?.deletedAt
          ? Number.parseInt(o.customMetadata.deletedAt, 10)
          : o.uploaded.getTime();
        return now - deletedAt > TRASH_RETENTION_MS;
      })
      .map((o: any) => o.key);
    if (expired.length > 0) await c.env.CLOUDSYNC_BUCKET.delete(expired);
  } catch {}
}

async function recordVaultChange(
  env: Bindings,
  userId: string,
  vault: string,
  key: string,
  action: "put" | "delete" | "cursor",
  mtime: number,
  size?: number,
  cursor?: { line: number; ch: number },
  device?: { deviceId: string; deviceName: string }
): Promise<number> {
  const rev = getNextRevision();
  const vaultKey = `${userId}:${vault}`;

  // Keep in-memory cache updated for fast local isolate lookups
  if (cursor && device?.deviceId) {
    let devMap = cursorCache.get(vaultKey);
    if (!devMap) {
      devMap = new Map();
      cursorCache.set(vaultKey, devMap);
    }
    devMap.set(device.deviceId, {
      key,
      cursor,
      deviceId: device.deviceId,
      deviceName: device.deviceName || "Remote Device",
      rev,
      timestamp: Date.now(),
    });
  }

  const metaKey = `users/${userId}/vaults/${vault}/.cloudsync_meta.json`;

  await withVaultLock(vaultKey, async () => {
    for (let attempt = 0; attempt < 8; attempt++) {
      const meta: {
        revision: number;
        changes: VaultChange[];
        presences: Record<string, CachedCursor>;
      } = { revision: rev, changes: [], presences: {} };
      let etag: string | undefined;

      try {
        const existing = await env.CLOUDSYNC_BUCKET.get(metaKey);
        if (existing) {
          etag = existing.etag;
          try {
            const parsed = (await existing.json()) as any;
            if (parsed?.changes && Array.isArray(parsed.changes)) {
              meta.changes = parsed.changes;
            }
            if (parsed?.presences && typeof parsed.presences === "object") {
              meta.presences = parsed.presences;
            }
          } catch {}
        }
      } catch {}

      const now = Date.now();
      for (const [devId, item] of Object.entries(meta.presences)) {
        if (now - item.timestamp > CURSOR_TTL_MS) {
          delete meta.presences[devId];
        }
      }

      if (cursor && device?.deviceId) {
        meta.presences[device.deviceId] = {
          key,
          cursor,
          deviceId: device.deviceId,
          deviceName: device.deviceName || "Remote Device",
          rev,
          timestamp: now,
        };
      }

      meta.revision = rev;
      meta.changes.unshift({
        rev,
        key,
        action,
        mtime,
        size,
        cursor,
        deviceId: device?.deviceId,
        deviceName: device?.deviceName,
      });
      if (meta.changes.length > 100) {
        meta.changes = meta.changes.slice(0, 100);
      }

      const value = JSON.stringify(meta);
      const baseOptions: any = {
        httpMetadata: { contentType: "application/json" },
        customMetadata: { revision: `${rev}` },
      };
      const options: any = etag
        ? { ...baseOptions, onlyIf: { etagMatches: etag } }
        : baseOptions;

      try {
        const res = await env.CLOUDSYNC_BUCKET.put(metaKey, value, options);
        if (res !== null) return;
        // Precondition failed: another writer updated the metadata; retry.
      } catch (err) {
        // Some storage backends do not support conditional writes; fall back once.
        try {
          await env.CLOUDSYNC_BUCKET.put(metaKey, value, baseOptions);
          return;
        } catch (err2) {
          console.error("Failed to record vault change:", err2);
          return;
        }
      }
    }
    console.warn(
      "Failed to record vault change after retries (metadata contention)"
    );
  });

  // NOTE: do not invalidate storageCache here. It is intentionally time-based
  // (see getUserStorageBytes) so uploads don't trigger a full bucket listing;
  // quota checks refresh it on demand before rejecting a write.

  return rev;
}

export interface VaultTarget {
  ownerId: string;
  vault: string;
  isOwner: boolean;
  ownerUsername: string;
}

// Protocol v2: key material, envelopes, vault rotation, object integrity

const MAX_KEY_MATERIAL_BYTES = 64 * 1024;
const MAX_ENVELOPE_BYTES = 8 * 1024;
const INTEGRITY_HEX_RE = /^[a-fA-F0-9]{64}$/;

interface VaultMarker {
  created?: number;
  name?: string;
  keyVersion?: number;
  rotating?: boolean;
  rotatingBy?: string;
  rotationStartedAt?: number;
}

function vaultMarkerKey(ownerId: string, vault: string): string {
  return `users/${ownerId}/vaults/${vault}/.cloudsync`;
}

async function readVaultMarker(
  c: any,
  ownerId: string,
  vault: string
): Promise<VaultMarker> {
  try {
    const obj = await c.env.CLOUDSYNC_BUCKET.get(
      vaultMarkerKey(ownerId, vault)
    );
    if (obj) {
      const parsed = (await obj.json()) as any;
      return {
        created:
          typeof parsed?.created === "number" ? parsed.created : undefined,
        name: typeof parsed?.name === "string" ? parsed.name : undefined,
        keyVersion:
          typeof parsed?.keyVersion === "number" ? parsed.keyVersion : 1,
        rotating: parsed?.rotating === true,
        rotatingBy:
          typeof parsed?.rotatingBy === "string"
            ? parsed.rotatingBy
            : undefined,
        rotationStartedAt:
          typeof parsed?.rotationStartedAt === "number"
            ? parsed.rotationStartedAt
            : undefined,
      };
    }
  } catch {}
  return { keyVersion: 1, rotating: false };
}

async function writeVaultMarker(
  c: any,
  ownerId: string,
  vault: string,
  patch: Partial<VaultMarker>
): Promise<VaultMarker> {
  const key = vaultMarkerKey(ownerId, vault);
  return await withVaultLock(`marker:${ownerId}:${vault}`, async () => {
    for (let attempt = 0; attempt < 8; attempt++) {
      let current: VaultMarker = {};
      let etag: string | undefined;
      try {
        const obj = await c.env.CLOUDSYNC_BUCKET.get(key);
        if (obj) {
          etag = obj.etag;
          try {
            current = (await obj.json()) as VaultMarker;
          } catch {}
        }
      } catch {}
      const next: VaultMarker = { ...current, ...patch };
      const baseOptions: any = {
        httpMetadata: { contentType: "application/json" },
      };
      const options: any = etag
        ? { ...baseOptions, onlyIf: { etagMatches: etag } }
        : baseOptions;
      try {
        const res = await c.env.CLOUDSYNC_BUCKET.put(
          key,
          JSON.stringify(next),
          options
        );
        if (res !== null) return next;
      } catch {
        try {
          await c.env.CLOUDSYNC_BUCKET.put(
            key,
            JSON.stringify(next),
            baseOptions
          );
          return next;
        } catch {}
      }
    }
    throw new Error("failed to update vault marker");
  });
}

/**
 * While a vault is being re-keyed, writes from ordinary clients are rejected.
 * The owner performing the rotation identifies itself with `x-rotation: 1`.
 */
async function assertVaultWritable(
  c: any,
  target: VaultTarget
): Promise<Response | null> {
  const marker = await readVaultMarker(c, target.ownerId, target.vault);
  if (marker.rotating) {
    if (target.isOwner && c.req.header("x-rotation") === "1") return null;
    return c.json(
      {
        error:
          "This vault is being re-keyed. Sync is paused; try again shortly.",
      },
      409
    );
  }
  // Reject writers that still hold a previous key generation. Without this a
  // sync that raced a re-key could write old-key objects into the new vault.
  const headerVersion = c.req.header("x-key-version");
  if (headerVersion !== undefined && headerVersion !== "") {
    const current = marker.keyVersion ?? 1;
    if (Number.parseInt(headerVersion, 10) !== current) {
      return c.json(
        {
          error: `This vault was re-keyed (key version ${current}). Sync again to fetch the new key.`,
        },
        409
      );
    }
  }
  return null;
}

function isValidKeyMaterial(value: any, userId: string): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (value.v !== 2) return false;
  if (value.accountId !== userId) return false;
  for (const field of ["wrappedMasterKey", "mac"] as const) {
    if (typeof value[field] !== "string" || value[field].length === 0)
      return false;
  }
  if (typeof value.kdf?.alg !== "string" || typeof value.kdf?.salt !== "string")
    return false;
  if (!value.identity || typeof value.identity.publicKey !== "string")
    return false;
  if (typeof value.identity.sealedPrivateKey !== "string") return false;
  if (
    !value.vaults ||
    typeof value.vaults !== "object" ||
    Array.isArray(value.vaults)
  )
    return false;
  for (const entry of Object.values(value.vaults) as any[]) {
    if (!entry || typeof entry !== "object") return false;
    if (
      typeof entry.wrappedKey !== "string" ||
      typeof entry.version !== "number"
    )
      return false;
  }
  if (typeof value.rev !== "number" || !Number.isFinite(value.rev))
    return false;
  return true;
}

function isValidEnvelope(
  value: any,
  ctx: { ownerId: string; vault: string; recipientId: string }
): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (value.v !== 2) return false;
  if (value.ownerId !== ctx.ownerId) return false;
  if (value.vaultId !== ctx.vault) return false;
  if (value.recipientId !== ctx.recipientId) return false;
  if (
    typeof value.keyVersion !== "number" ||
    !Number.isFinite(value.keyVersion)
  )
    return false;
  if (typeof value.sender !== "string" || value.sender.length === 0)
    return false;
  if (typeof value.sealed !== "string" || value.sealed.length === 0)
    return false;
  return true;
}

function keyMaterialStorageKey(userId: string): string {
  return `keymaterial:${userId}`;
}

function userPublicKeyStorageKey(usernameLower: string): string {
  return `user_pubkey:${usernameLower}`;
}

function vaultEnvelopeStorageKey(
  ownerId: string,
  vault: string,
  recipientId: string
): string {
  return `vault_envelope:${ownerId}:${vault}:${recipientId}`;
}

function vaultEnvelopeIndexKey(ownerId: string, vault: string): string {
  return `vault_envelopes_index:${ownerId}:${vault}`;
}

async function deleteVaultEnvelopeFor(
  c: any,
  ownerId: string,
  vault: string,
  recipientId: string
): Promise<void> {
  await deleteStoredData(
    c,
    vaultEnvelopeStorageKey(ownerId, vault, recipientId)
  );
  await withVaultLock(`envelopes:${ownerId}:${vault}`, async () => {
    const idxRaw = await getStoredData(
      c,
      vaultEnvelopeIndexKey(ownerId, vault)
    );
    if (!idxRaw) return;
    try {
      const ids: string[] = JSON.parse(idxRaw);
      const next = ids.filter((id) => id !== recipientId);
      if (next.length !== ids.length) {
        await putStoredData(
          c,
          vaultEnvelopeIndexKey(ownerId, vault),
          JSON.stringify(next)
        );
      }
    } catch {}
  });
}

async function deleteAllVaultEnvelopes(
  c: any,
  ownerId: string,
  vault: string
): Promise<void> {
  try {
    const idxRaw = await getStoredData(
      c,
      vaultEnvelopeIndexKey(ownerId, vault)
    );
    const ids: string[] = idxRaw ? JSON.parse(idxRaw) : [];
    for (const id of ids) {
      await deleteStoredData(c, vaultEnvelopeStorageKey(ownerId, vault, id));
    }
    await deleteStoredData(c, vaultEnvelopeIndexKey(ownerId, vault));
  } catch (err) {
    console.error("Failed to clean up vault key envelopes:", err);
  }
}

async function resolveVaultTarget(
  c: any,
  vaultName: string,
  requestedOwner?: string
): Promise<{ target?: VaultTarget; error?: string; status?: number }> {
  if (!isValidVaultName(vaultName)) {
    return { error: "Invalid vault identifier.", status: 400 };
  }

  const callerId = c.get("userId");
  const callerUsername = (c.get("username") || "").toLowerCase();

  // If requestedOwner is provided and not caller:
  if (
    requestedOwner &&
    requestedOwner.trim().toLowerCase() !== callerUsername
  ) {
    const ownerNameNorm = requestedOwner.trim().toLowerCase();
    const ownerUserRaw = await getStoredData(c, `user:${ownerNameNorm}`);
    if (!ownerUserRaw) {
      return {
        error: `Vault owner "${requestedOwner}" not found.`,
        status: 404,
      };
    }
    let ownerUser: any = null;
    try {
      ownerUser = JSON.parse(ownerUserRaw);
    } catch {}
    if (!ownerUser || !ownerUser.id) {
      return {
        error: `Vault owner "${requestedOwner}" not found.`,
        status: 404,
      };
    }

    const sharesRaw = await getStoredData(
      c,
      `vault_shares:${ownerUser.id}:${vaultName}`
    );
    const shares: string[] = sharesRaw ? JSON.parse(sharesRaw) : [];
    const isShared = shares.some((u) => u.toLowerCase() === callerUsername);
    if (!isShared) {
      return {
        error: "You do not have access to this shared vault.",
        status: 403,
      };
    }

    return {
      target: {
        ownerId: ownerUser.id,
        vault: vaultName,
        isOwner: false,
        ownerUsername: ownerUser.username,
      },
    };
  }

  // If requestedOwner is not provided, check if this vault is a shared vault for the caller
  if (!requestedOwner) {
    try {
      const owned = await c.env.CLOUDSYNC_BUCKET.head(
        `users/${callerId}/vaults/${vaultName}/.cloudsync`
      );
      if (!owned) {
        const sharedRaw = await getStoredData(
          c,
          `user_shared_vaults:${callerId}`
        );
        if (sharedRaw) {
          const sharedList: Array<{
            vault: string;
            ownerId: string;
            ownerUsername: string;
          }> = JSON.parse(sharedRaw);
          const match = sharedList.find(
            (s) => s.vault.toLowerCase() === vaultName.toLowerCase()
          );
          if (match) {
            const sharesRaw = await getStoredData(
              c,
              `vault_shares:${match.ownerId}:${match.vault}`
            );
            const shares: string[] = sharesRaw ? JSON.parse(sharesRaw) : [];
            if (shares.some((u) => u.toLowerCase() === callerUsername)) {
              return {
                target: {
                  ownerId: match.ownerId,
                  vault: match.vault,
                  isOwner: false,
                  ownerUsername: match.ownerUsername,
                },
              };
            }
          }
        }
      }
    } catch {}
  }

  return {
    target: {
      ownerId: callerId,
      vault: vaultName,
      isOwner: true,
      ownerUsername: callerUsername,
    },
  };
}

// Info & health
app.get("/", (c) => {
  return c.json({
    status: "ok",
    service: "CloudSync Edge Worker",
    version: "3.0.0",
    mode: c.env.WORKER_MODE === "single" ? "single" : "multi",
  });
});

app.get("/api/info", async (c) => {
  const mode = c.env.WORKER_MODE === "single" ? "single" : "multi";
  let hasPassword = true;
  if (mode === "single") {
    if (c.env.SINGLE_USER_PASSWORD) {
      hasPassword = true;
    } else {
      const stored = await getStoredData(c, "single:verifier");
      hasPassword = !!stored;
    }
  }
  return c.json({
    status: "ok",
    service: "CloudSync",
    version: "3.0.0",
    mode,
    requiresSetup: mode === "single" && !hasPassword,
  });
});

// Auth endpoints
app.post("/api/auth/single-login", async (c) => {
  const clientIp = checkAuthRateLimitKey(c);
  if (!checkAuthRateLimit(clientIp)) {
    return c.json(
      {
        error:
          "Too many authentication attempts. Please try again in a minute.",
      },
      429
    );
  }

  let body: { verifier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const verifier = (body?.verifier || "").trim();
  if (!verifier || !isValidHexHash(verifier)) {
    return c.json(
      { error: "Valid 64-character password verifier required." },
      400
    );
  }

  const secret = getJwtSecret(c);
  const hashed = await hashVerifier(verifier, secret);
  const configuredPassword = c.env.SINGLE_USER_PASSWORD;

  let authorized = false;
  if (configuredPassword) {
    // The env var is authoritative: compare the client verifier with the one derived
    // from the configured password (same derivation the plugin uses for account "default").
    const expectedVerifier = await deriveAuthVerifier(
      configuredPassword,
      "default"
    );
    authorized = expectedVerifier === verifier.toLowerCase();
  } else {
    const stored = await getStoredData(c, "single:verifier");
    if (!stored) {
      return c.json(
        {
          error:
            "Single-user setup is not configured. Set SINGLE_USER_PASSWORD on the server before first login.",
        },
        403
      );
    }
    // Legacy support for deployments that stored the verifier before this check existed.
    authorized = stored === hashed || stored === verifier.toLowerCase();
  }

  if (!authorized) {
    return c.json({ error: "Invalid master password." }, 401);
  }

  const now = Date.now();
  const token = await signJwt(
    {
      sub: "default",
      username: "Owner",
      iat: Math.floor(now / 1000),
      exp: Math.floor(now / 1000) + 86400 * 180,
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: "default", username: "Owner" },
  });
});

app.post("/api/auth/register", async (c) => {
  const clientIp = checkAuthRateLimitKey(c);
  if (!checkAuthRateLimit(clientIp)) {
    return c.json(
      {
        error: "Too many registration attempts. Please try again in a minute.",
      },
      429
    );
  }

  let body: {
    username?: string;
    verifier?: string;
    recoveryVerifier?: string;
    totpSecret?: string;
    scheme?: number;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const username = (body?.username || "").trim();
  const verifier = (body?.verifier || "").trim();
  const recoveryVerifier = (body?.recoveryVerifier || "").trim();
  const totpSecret = (body?.totpSecret || "").trim();
  const scheme = body?.scheme === 2 ? 2 : 1;

  if (!username || !verifier) {
    return c.json(
      { error: "Username and password verifier are required." },
      400
    );
  }
  if (!isValidUsername(username) || !isValidHexHash(verifier)) {
    return c.json({ error: "Invalid username or verifier format." }, 400);
  }
  if (recoveryVerifier && !isValidHexHash(recoveryVerifier)) {
    return c.json({ error: "Invalid recovery verifier format." }, 400);
  }
  if (totpSecret && !isValidTotpSecret(totpSecret)) {
    return c.json({ error: "Invalid TOTP secret format." }, 400);
  }

  const secret = getJwtSecret(c);
  const userKey = `user:${username.toLowerCase()}`;

  const existing = await getStoredData(c, userKey);
  if (existing) {
    return c.json({ error: "Username already taken." }, 409);
  }

  const userId = crypto.randomUUID();
  const userData = {
    id: userId,
    username,
    scheme,
    verifier: await hashVerifier(verifier, secret),
    recoveryVerifier: recoveryVerifier
      ? await hashVerifier(recoveryVerifier, secret)
      : undefined,
    totpSecret: totpSecret || undefined,
    created: Date.now(),
  };

  await putStoredData(c, userKey, JSON.stringify(userData));

  const nowSec = Math.floor(Date.now() / 1000);
  const token = await signJwt(
    { sub: userId, username, iat: nowSec, exp: nowSec + 86400 * 180 },
    secret
  );

  return c.json({ ok: true, token, user: { id: userId, username } });
});

app.post("/api/auth/login", async (c) => {
  const clientIp = checkAuthRateLimitKey(c);
  if (!checkAuthRateLimit(clientIp)) {
    return c.json(
      { error: "Too many login attempts. Please try again in a minute." },
      429
    );
  }
  let body: { username?: string; verifier?: string; totpCode?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const username = (body?.username || "").trim();
  const verifier = (body?.verifier || "").trim();
  const totpCode = (body?.totpCode || "").trim();

  if (!username || !verifier) {
    return c.json(
      { error: "Username and password verifier are required." },
      400
    );
  }

  const secret = getJwtSecret(c);
  const userKey = `user:${username.toLowerCase()}`;
  let user: any = null;

  const raw = await getStoredData(c, userKey);
  if (raw) {
    try {
      user = JSON.parse(raw);
    } catch {}
  }

  if (!user) {
    return c.json({ error: "Invalid username or password." }, 401);
  }

  const hashed = await hashVerifier(verifier, secret);
  if (user.verifier !== hashed && user.verifier !== verifier.toLowerCase()) {
    if (user.scheme === 2) {
      return c.json(
        {
          error:
            "Incorrect password, or this plugin version is too old for this account.",
        },
        401
      );
    }
    return c.json({ error: "Invalid username or password." }, 401);
  }

  if (user.totpSecret) {
    if (!totpCode) {
      return c.json({ error: "2FA code required.", requires2FA: true }, 200);
    }
    const valid = await verifyTotpCode(user.totpSecret, totpCode);
    if (!valid) {
      return c.json({ error: "Invalid 2FA code." }, 401);
    }
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const token = await signJwt(
    {
      sub: user.id,
      username: user.username,
      iat: nowSec,
      exp: nowSec + 86400 * 180,
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: user.id, username: user.username },
  });
});

app.post("/api/auth/recover", async (c) => {
  const clientIp = checkAuthRateLimitKey(c);
  if (!checkAuthRateLimit(clientIp, 10, 60_000)) {
    return c.json(
      { error: "Too many recovery attempts. Please try again in a minute." },
      429
    );
  }

  let body: {
    username?: string;
    recoveryVerifier?: string;
    totpCode?: string;
    newVerifier?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const username = (body?.username || "").trim();
  const recoveryVerifier = (body?.recoveryVerifier || "").trim();
  const totpCode = (body?.totpCode || "").trim();
  const newVerifier = (body?.newVerifier || "").trim();

  if (!username || !newVerifier || (!recoveryVerifier && !totpCode)) {
    return c.json(
      {
        error:
          "Username, a recovery key or 2FA code, and a new password are required.",
      },
      400
    );
  }
  if (!isValidUsername(username) || !isValidHexHash(newVerifier)) {
    return c.json({ error: "Invalid username or new verifier format." }, 400);
  }
  if (recoveryVerifier && !isValidHexHash(recoveryVerifier)) {
    return c.json({ error: "Invalid recovery verifier format." }, 400);
  }

  const secret = getJwtSecret(c);
  const userKey = `user:${username.toLowerCase()}`;
  let user: any = null;

  const raw = await getStoredData(c, userKey);
  if (raw) {
    try {
      user = JSON.parse(raw);
    } catch {}
  }

  if (!user) {
    return c.json({ error: "Invalid recovery key or user not found." }, 401);
  }

  let authorized = false;
  if (totpCode) {
    if (!user.totpSecret || !isValidTotpCode(totpCode)) {
      return c.json({ error: "Invalid 2FA code." }, 401);
    }
    authorized = await verifyTotpCode(user.totpSecret, totpCode);
  } else if (user.recoveryVerifier) {
    const hashedRecovery = await hashVerifier(recoveryVerifier, secret);
    authorized =
      user.recoveryVerifier === hashedRecovery ||
      user.recoveryVerifier === recoveryVerifier.toLowerCase();
  }

  if (!authorized) {
    return c.json({ error: "Invalid recovery key or 2FA code." }, 401);
  }

  const now = Date.now();
  user.verifier = await hashVerifier(newVerifier, secret);
  user.pwdAt = now;
  await putStoredData(c, userKey, JSON.stringify(user));

  const nowSec = Math.floor(now / 1000);
  const token = await signJwt(
    {
      sub: user.id,
      username: user.username,
      iat: nowSec,
      exp: nowSec + 86400 * 180,
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: user.id, username: user.username },
  });
});

// Set or rotate the recovery key (authenticated)
app.post("/api/user/recovery-key", async (c) => {
  const username = c.get("username");
  let body: { recoveryVerifier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }
  const recoveryVerifier = (body?.recoveryVerifier || "").trim();
  if (!isValidHexHash(recoveryVerifier)) {
    return c.json(
      { error: "Valid 64-character recovery verifier required." },
      400
    );
  }

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await getStoredData(c, userKey);
  if (!raw) return c.json({ error: "User not found." }, 404);

  const secret = getJwtSecret(c);
  const user = JSON.parse(raw);
  user.recoveryVerifier = await hashVerifier(recoveryVerifier, secret);
  await putStoredData(c, userKey, JSON.stringify(user));

  return c.json({ ok: true, message: "Recovery key updated." });
});

/**
 * Returns the (non-secret) KDF descriptor for an account so any device can
 * derive the login verifier. scheme 1 means a pre-v2 account.
 */
app.get("/api/auth/params/:username", async (c) => {
  const clientIp = checkAuthRateLimitKey(c);
  if (!checkAuthRateLimit(clientIp, 60, 60_000)) {
    return c.json(
      { error: "Too many requests. Please try again in a minute." },
      429
    );
  }
  const requested = c.req.param("username").trim().toLowerCase();
  if (!isValidUsername(requested)) {
    return c.json({ error: "Invalid username." }, 400);
  }
  const lookupName = requested === "default" ? "owner" : requested;
  const kdfRaw = await getStoredData(c, `user_kdf:${lookupName}`);
  if (!kdfRaw) {
    return c.json({ ok: true, scheme: 1, kdf: null });
  }
  try {
    return c.json({ ok: true, scheme: 2, kdf: JSON.parse(kdfRaw) });
  } catch {
    return c.json({ ok: true, scheme: 1, kdf: null });
  }
});

app.get("/api/auth/verify-token", async (c) => {
  const auth = c.req.header("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return c.json({ valid: false }, 401);

  const secret = getJwtSecret(c);
  const payload = await verifyJwt(match[1], secret);
  if (!payload) return c.json({ valid: false }, 401);

  return c.json({
    valid: true,
    userId: payload.sub,
    username: payload.username,
  });
});

// Authenticated route guard
app.use("/api/*", async (c, next) => {
  const path = c.req.path;
  if (
    path.startsWith("/api/auth/") ||
    path === "/api/info" ||
    (path.startsWith("/api/user/avatar/") &&
      c.req.method.toUpperCase() === "GET") ||
    (path.startsWith("/api/user/profile/") &&
      c.req.method.toUpperCase() === "GET")
  ) {
    return await next();
  }

  const auth = c.req.header("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return c.json({ error: "Unauthorized: Missing Bearer token." }, 401);
  }

  const secret = getJwtSecret(c);
  const payload = await verifyJwt(match[1], secret);
  if (!payload || !payload.sub) {
    return c.json({ error: "Unauthorized: Invalid or expired token." }, 401);
  }

  // Invalidate tokens issued before the last password change / recovery.
  const uname = (payload.username || "").toLowerCase();
  if (uname && uname !== "owner") {
    const raw = await getStoredData(c, `user:${uname}`);
    if (raw) {
      try {
        const user = JSON.parse(raw);
        if (user.pwdAt && payload.iat && payload.iat * 1000 < user.pwdAt) {
          return c.json(
            { error: "Unauthorized: Session expired after password change." },
            401
          );
        }
      } catch {}
    }
  }

  c.set("userId", payload.sub);
  c.set("username", payload.username || "User");
  await next();
});

// While a vault is being re-keyed, all sync traffic is paused (reads included)
// except for the rotation client, which identifies itself with x-rotation.
app.use("/api/sync/*", async (c, next) => {
  if (c.req.header("x-rotation") === "1") return await next();
  const vault = c.req.query("vault");
  if (!vault) return await next();
  const res = await resolveVaultTarget(c, vault, c.req.query("owner"));
  if (!res.error && res.target) {
    const marker = await readVaultMarker(
      c,
      res.target.ownerId,
      res.target.vault
    );
    if (marker.rotating) {
      return c.json(
        {
          error:
            "This vault is being re-keyed. Sync is paused; try again shortly.",
        },
        409
      );
    }
  }
  await next();
});

// User profile & storage
app.get("/api/user/me", async (c) => {
  const userId = c.get("userId");
  const username = c.get("username");

  let storageUsedBytes = 0;
  const cached = storageCache.get(userId);
  if (cached && Date.now() - cached.timestamp < 300_000) {
    storageUsedBytes = cached.bytes;
  } else {
    let cursor: string | undefined = undefined;
    let truncated = true;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({
        prefix: `users/${userId}/`,
        cursor,
        limit: 1000,
      });
      for (const obj of list.objects) storageUsedBytes += obj.size;
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
    storageCache.set(userId, {
      bytes: storageUsedBytes,
      timestamp: Date.now(),
    });
  }

  let has2FA = false;
  let displayName = username;
  if (username && username !== "Owner") {
    const raw = await getStoredData(c, `user:${username.toLowerCase()}`);
    if (raw) {
      try {
        const u = JSON.parse(raw);
        has2FA = Boolean(u.totpSecret);
        if (u.displayName) displayName = u.displayName;
      } catch {}
    }
  }

  let hasAvatar = false;
  if (username) {
    const avatarRaw = await getStoredData(
      c,
      `user_avatar:${username.toLowerCase()}`
    );
    hasAvatar = Boolean(avatarRaw);
  }

  const hasKeyMaterial = Boolean(
    await getStoredData(c, keyMaterialStorageKey(userId))
  );

  return c.json({
    ok: true,
    userId,
    username,
    displayName,
    has2FA,
    hasAvatar,
    hasKeyMaterial,
    storageUsedBytes,
    quotaBytes: 10 * 1024 * 1024 * 1024,
  });
});

app.post("/api/user/setup-2fa", async (c) => {
  const username = c.get("username");
  let body: { totpSecret?: string; totpCode?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const totpSecret = (body?.totpSecret || "").trim();
  const totpCode = (body?.totpCode || "").trim();

  if (!isValidTotpSecret(totpSecret) || !isValidTotpCode(totpCode)) {
    return c.json({ error: "Invalid 2FA secret or 6-digit code." }, 400);
  }

  const valid = await verifyTotpCode(totpSecret, totpCode);
  if (!valid) {
    return c.json({ error: "Invalid 2FA code." }, 400);
  }

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await getStoredData(c, userKey);
  if (!raw) return c.json({ error: "User not found." }, 404);

  const user = JSON.parse(raw);
  user.totpSecret = totpSecret;
  await putStoredData(c, userKey, JSON.stringify(user));

  return c.json({ ok: true, message: "Two-factor authentication enabled." });
});

app.post("/api/user/disable-2fa", async (c) => {
  const username = c.get("username");
  let body: { totpCode?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const totpCode = (body?.totpCode || "").trim();
  const userKey = `user:${username.toLowerCase()}`;
  const raw = await getStoredData(c, userKey);
  if (!raw) return c.json({ error: "User not found." }, 404);

  const user = JSON.parse(raw);
  if (!user.totpSecret) return c.json({ ok: true });

  const valid = await verifyTotpCode(user.totpSecret, totpCode);
  if (!valid) return c.json({ error: "Invalid 2FA code." }, 400);

  delete user.totpSecret;
  await putStoredData(c, userKey, JSON.stringify(user));

  return c.json({ ok: true, message: "Two-factor authentication disabled." });
});

app.post("/api/user/change-password", async (c) => {
  const username = c.get("username");
  let body: { oldVerifier?: string; newVerifier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const oldVerifier = (body?.oldVerifier || "").trim();
  const newVerifier = (body?.newVerifier || "").trim();

  if (!isValidHexHash(oldVerifier) || !isValidHexHash(newVerifier)) {
    return c.json({ error: "Valid 64-character verifiers required." }, 400);
  }

  const secret = getJwtSecret(c);
  const userKey = `user:${username.toLowerCase()}`;
  const raw = await getStoredData(c, userKey);
  if (!raw) return c.json({ error: "User not found." }, 404);

  const user = JSON.parse(raw);
  const oldHashed = await hashVerifier(oldVerifier, secret);
  if (
    user.verifier !== oldHashed &&
    user.verifier !== oldVerifier.toLowerCase()
  ) {
    return c.json({ error: "Incorrect current password." }, 401);
  }

  user.verifier = await hashVerifier(newVerifier, secret);
  user.pwdAt = Date.now();
  await putStoredData(c, userKey, JSON.stringify(user));

  return c.json({
    ok: true,
    message:
      "Password updated successfully. Other sessions have been signed out.",
  });
});

// Protocol v2 key material: opaque to the server; only the client can read it.
app.get("/api/user/keymaterial", async (c) => {
  const userId = c.get("userId");
  const raw = await getStoredData(c, keyMaterialStorageKey(userId));
  if (!raw) return c.json({ ok: true, keyMaterial: null });
  try {
    return c.json({ ok: true, keyMaterial: JSON.parse(raw) });
  } catch {
    return c.json({ ok: true, keyMaterial: null });
  }
});

app.put("/api/user/keymaterial", async (c) => {
  const userId = c.get("userId");
  const username = (c.get("username") || "").toLowerCase();
  let body: { keyMaterial?: any };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const keyMaterial = body?.keyMaterial;
  if (!isValidKeyMaterial(keyMaterial, userId)) {
    return c.json({ error: "Invalid key material payload." }, 400);
  }
  const serialized = JSON.stringify(keyMaterial);
  if (serialized.length > MAX_KEY_MATERIAL_BYTES) {
    return c.json({ error: "Key material exceeds the maximum size." }, 413);
  }

  const result = await withVaultLock(`keymaterial:${userId}`, async () => {
    const existing = await getStoredData(c, keyMaterialStorageKey(userId));
    if (existing) {
      try {
        const parsed = JSON.parse(existing);
        if (typeof parsed?.rev === "number" && keyMaterial.rev <= parsed.rev) {
          return "stale";
        }
      } catch {}
    }
    await putStoredData(c, keyMaterialStorageKey(userId), serialized);
    await putStoredData(
      c,
      `user_kdf:${username}`,
      JSON.stringify(keyMaterial.kdf)
    );
    await putStoredData(
      c,
      userPublicKeyStorageKey(username),
      JSON.stringify({
        username,
        userId,
        publicKey: keyMaterial.identity.publicKey,
        updatedAt: Date.now(),
      })
    );
    return "ok";
  });

  if (result === "stale") {
    return c.json(
      { error: "Stale key material revision; reload before writing." },
      409
    );
  }
  return c.json({ ok: true, rev: keyMaterial.rev });
});

app.get("/api/user/pubkey/:username", async (c) => {
  const username = c.req.param("username");
  if (!isValidUsername(username)) {
    return c.json({ error: "Invalid username." }, 400);
  }
  const raw = await getStoredData(
    c,
    userPublicKeyStorageKey(username.toLowerCase())
  );
  if (!raw) {
    return c.json({ error: "No public key for this user." }, 404);
  }
  try {
    return c.json({ ok: true, ...JSON.parse(raw) });
  } catch {
    return c.json({ error: "Corrupted public key record." }, 500);
  }
});

// Profile picture & avatar management
const MAX_AVATAR_SIZE = 512 * 1024; // 512 KB

app.get("/api/user/avatar/:username", async (c) => {
  const username = c.req.param("username");
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(username)) {
    return c.json({ error: "Invalid username." }, 400);
  }

  const metaRaw = await getStoredData(
    c,
    `user_avatar:${username.toLowerCase()}`
  );
  if (!metaRaw) {
    return c.json({ error: "Avatar not found." }, 404);
  }

  let meta: { userId: string; mime: string };
  try {
    meta = JSON.parse(metaRaw);
  } catch {
    return c.json({ error: "Corrupted avatar metadata." }, 500);
  }

  const obj = await c.env.CLOUDSYNC_BUCKET.get(`users/${meta.userId}/avatar`);
  if (!obj) {
    return c.json({ error: "Avatar not found." }, 404);
  }

  const body = await obj.arrayBuffer();
  return new Response(body, {
    headers: {
      "Content-Type": meta.mime || "image/png",
      "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; sandbox",
      "Content-Disposition": "inline",
    },
  });
});

app.post("/api/user/avatar", async (c) => {
  const userId = c.get("userId");
  const username = c.get("username");

  const contentLength = Number(c.req.header("content-length") || "0");
  if (contentLength > MAX_AVATAR_SIZE) {
    return c.json(
      { error: "Avatar image exceeds maximum size of 512KB." },
      413
    );
  }

  let buffer: ArrayBuffer;
  try {
    buffer = await c.req.arrayBuffer();
  } catch {
    return c.json({ error: "Failed to read image payload." }, 400);
  }

  if (buffer.byteLength === 0) {
    return c.json({ error: "Empty image payload." }, 400);
  }

  if (buffer.byteLength > MAX_AVATAR_SIZE) {
    return c.json(
      { error: "Avatar image exceeds maximum size of 512KB." },
      413
    );
  }

  const imageInfo = detectSafeImageType(new Uint8Array(buffer));
  if (!imageInfo) {
    return c.json(
      {
        error:
          "Invalid or unsafe image file. Supported formats: PNG, JPEG, WebP, GIF.",
      },
      400
    );
  }

  await c.env.CLOUDSYNC_BUCKET.put(`users/${userId}/avatar`, buffer, {
    httpMetadata: { contentType: imageInfo.mime },
  });

  await putStoredData(
    c,
    `user_avatar:${username.toLowerCase()}`,
    JSON.stringify({ userId, mime: imageInfo.mime, updatedAt: Date.now() })
  );

  return c.json({ ok: true, message: "Avatar uploaded successfully." });
});

app.delete("/api/user/avatar", async (c) => {
  const userId = c.get("userId");
  const username = c.get("username");

  try {
    await c.env.CLOUDSYNC_BUCKET.delete(`users/${userId}/avatar`);
  } catch (e) {
    console.warn("Failed to delete avatar from bucket:", e);
  }

  await deleteStoredData(c, `user_avatar:${username.toLowerCase()}`);
  return c.json({ ok: true, message: "Avatar removed." });
});

// User profile details (Display Name)
app.post("/api/user/profile", async (c) => {
  const username = c.get("username");
  let body: { displayName?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const displayName = (body?.displayName || "").trim();
  if (displayName.length > 64) {
    return c.json({ error: "Display name cannot exceed 64 characters." }, 400);
  }

  const sanitizedName = displayName.replace(/[<>]/g, "");

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await getStoredData(c, userKey);
  if (!raw) {
    return c.json({ error: "User not found." }, 404);
  }

  const user = JSON.parse(raw);
  user.displayName = sanitizedName;
  await putStoredData(c, userKey, JSON.stringify(user));

  return c.json({ ok: true, displayName: user.displayName });
});

app.get("/api/user/profile/:username", async (c) => {
  const username = c.req.param("username");
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(username)) {
    return c.json({ error: "Invalid username." }, 400);
  }

  const raw = await getStoredData(c, `user:${username.toLowerCase()}`);
  if (!raw) {
    return c.json({ error: "User not found." }, 404);
  }

  let user: any;
  try {
    user = JSON.parse(raw);
  } catch {
    return c.json({ error: "Corrupted user record." }, 500);
  }

  const avatarRaw = await getStoredData(
    c,
    `user_avatar:${username.toLowerCase()}`
  );

  return c.json({
    ok: true,
    username: user.username,
    displayName: user.displayName || user.username,
    hasAvatar: Boolean(avatarRaw),
  });
});

// Vault management
app.get("/api/vaults", async (c) => {
  const userId = c.get("userId");
  const currentUsername = c.get("username") || "";
  const vaultNamesSet = new Set<string>();

  try {
    const listed = await c.env.CLOUDSYNC_BUCKET.list({
      prefix: `users/${userId}/vaults/`,
      delimiter: "/",
    });
    if (listed.delimitedPrefixes) {
      for (const p of listed.delimitedPrefixes) {
        const name = p.split("/")[3];
        if (name && isValidVaultName(name)) vaultNamesSet.add(name);
      }
    }
  } catch (err) {
    console.error("Failed to list vault prefixes:", err);
  }

  const ownedVaults = await Promise.all(
    Array.from(vaultNamesSet).map(async (name) => {
      let revision = 0;
      try {
        const metaObj = await c.env.CLOUDSYNC_BUCKET.get(
          `users/${userId}/vaults/${name}/.cloudsync_meta.json`
        );
        if (metaObj) {
          const meta = (await metaObj.json()) as any;
          if (meta?.revision) revision = meta.revision;
        }
      } catch {}
      const marker = await readVaultMarker(c, userId, name);
      return {
        name,
        revision,
        isShared: false,
        owner: currentUsername,
        keyVersion: marker.keyVersion ?? 1,
        rotating: marker.rotating === true,
        rotatingBy: marker.rotatingBy,
        rotationStartedAt: marker.rotationStartedAt,
      };
    })
  );

  const sharedVaults: any[] = [];
  try {
    const sharedRaw = await getStoredData(c, `user_shared_vaults:${userId}`);
    if (sharedRaw) {
      const sharedList: Array<{
        vault: string;
        ownerId: string;
        ownerUsername: string;
      }> = JSON.parse(sharedRaw);
      for (const item of sharedList) {
        const sharesRaw = await getStoredData(
          c,
          `vault_shares:${item.ownerId}:${item.vault}`
        );
        const shares: string[] = sharesRaw ? JSON.parse(sharesRaw) : [];
        if (
          shares.some((u) => u.toLowerCase() === currentUsername.toLowerCase())
        ) {
          let revision = 0;
          try {
            const metaObj = await c.env.CLOUDSYNC_BUCKET.get(
              `users/${item.ownerId}/vaults/${item.vault}/.cloudsync_meta.json`
            );
            if (metaObj) {
              const meta = (await metaObj.json()) as any;
              if (meta?.revision) revision = meta.revision;
            }
          } catch {}
          const marker = await readVaultMarker(c, item.ownerId, item.vault);
          sharedVaults.push({
            name: item.vault,
            revision,
            isShared: true,
            owner: item.ownerUsername,
            ownerId: item.ownerId,
            keyVersion: marker.keyVersion ?? 1,
            rotating: marker.rotating === true,
            rotatingBy: marker.rotatingBy,
          });
        }
      }
    }
  } catch (err) {
    console.error("Failed to list shared vaults:", err);
  }

  return c.json({ ok: true, vaults: [...ownedVaults, ...sharedVaults] });
});

app.post("/api/vaults", async (c) => {
  const userId = c.get("userId");
  let body: { name?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const name = (body?.name || "").trim();
  if (!isValidVaultName(name)) {
    return c.json({ error: "Invalid vault name." }, 400);
  }

  const now = Date.now();
  await c.env.CLOUDSYNC_BUCKET.put(
    `users/${userId}/vaults/${name}/.cloudsync`,
    JSON.stringify({ created: now, name, keyVersion: 1, rotating: false }),
    { customMetadata: { created: `${now}` } }
  );
  await c.env.CLOUDSYNC_BUCKET.put(
    `users/${userId}/vaults/${name}/.cloudsync_meta.json`,
    JSON.stringify({ revision: now, changes: [] }),
    { httpMetadata: { contentType: "application/json" } }
  );

  return c.json({ ok: true, name });
});

app.delete("/api/vaults/:vaultName", async (c) => {
  const userId = c.get("userId");
  const vaultName = c.req.param("vaultName");
  if (!isValidVaultName(vaultName)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  // Clean up collaborator reverse indices
  try {
    const sharesKey = `vault_shares:${userId}:${vaultName}`;
    const rawShares = await getStoredData(c, sharesKey);
    if (rawShares) {
      const shares: string[] = JSON.parse(rawShares);
      for (const username of shares) {
        const uRaw = await getStoredData(c, `user:${username.toLowerCase()}`);
        if (uRaw) {
          const u = JSON.parse(uRaw);
          const inviteeSharesKey = `user_shared_vaults:${u.id}`;
          const inviteeRaw = await getStoredData(c, inviteeSharesKey);
          if (inviteeRaw) {
            let list: any[] = JSON.parse(inviteeRaw);
            list = list.filter(
              (s) => !(s.vault === vaultName && s.ownerId === userId)
            );
            await putStoredData(c, inviteeSharesKey, JSON.stringify(list));
          }
        }
      }
      await deleteStoredData(c, sharesKey);
    }
  } catch (err) {
    console.error("Failed to clean up vault shares on delete:", err);
  }

  try {
    await deleteStoredData(c, `vault_devices:${userId}:${vaultName}`);
  } catch {}

  await deleteAllVaultEnvelopes(c, userId, vaultName);

  const prefixes = [
    `users/${userId}/vaults/${vaultName}/`,
    `users/${userId}/history/${vaultName}/`,
    `users/${userId}/trash/${vaultName}/`,
  ];

  for (const prefix of prefixes) {
    let truncated = true;
    let cursor: string | undefined = undefined;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({
        prefix,
        cursor,
        limit: 500,
      });
      const keys = list.objects.map((o) => o.key);
      if (keys.length > 0) await c.env.CLOUDSYNC_BUCKET.delete(keys);
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
  }

  cursorCache.delete(`${userId}:${vaultName}`);
  storageCache.delete(userId);

  return c.json({ ok: true, deleted: vaultName });
});

// Protocol v2: vault key envelopes (owner writes, invited member reads own)
app.get("/api/vaults/:vaultName/envelope", async (c) => {
  const vaultName = c.req.param("vaultName");
  if (!isValidVaultName(vaultName)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }
  const res = await resolveVaultTarget(c, vaultName, c.req.query("owner"));
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (res.target.isOwner) {
    return c.json({ ok: true, envelope: null });
  }
  const callerId = c.get("userId");
  const raw = await getStoredData(
    c,
    vaultEnvelopeStorageKey(res.target.ownerId, res.target.vault, callerId)
  );
  if (!raw) return c.json({ ok: true, envelope: null });
  try {
    return c.json({ ok: true, envelope: JSON.parse(raw) });
  } catch {
    return c.json({ ok: true, envelope: null });
  }
});

app.put("/api/vaults/:vaultName/envelope/:recipientUsername", async (c) => {
  const vaultName = c.req.param("vaultName");
  const recipientUsername = c.req.param("recipientUsername");
  if (!isValidVaultName(vaultName) || !isValidUsername(recipientUsername)) {
    return c.json({ error: "Invalid parameters." }, 400);
  }
  const res = await resolveVaultTarget(c, vaultName);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json(
      { error: "Only the vault owner can store key envelopes." },
      403
    );
  }
  const currentUsername = (c.get("username") || "").toLowerCase();
  if (recipientUsername.toLowerCase() === currentUsername) {
    return c.json({ error: "You cannot store an envelope for yourself." }, 400);
  }

  const recipientRaw = await getStoredData(
    c,
    `user:${recipientUsername.toLowerCase()}`
  );
  let recipient: any = null;
  try {
    recipient = recipientRaw ? JSON.parse(recipientRaw) : null;
  } catch {}
  if (!recipient?.id) {
    return c.json(
      { error: `User "${recipientUsername}" does not exist.` },
      404
    );
  }

  const sharesRaw = await getStoredData(
    c,
    `vault_shares:${res.target.ownerId}:${res.target.vault}`
  );
  const shares: string[] = sharesRaw ? JSON.parse(sharesRaw) : [];
  if (
    !shares.some((u) => u.toLowerCase() === recipientUsername.toLowerCase())
  ) {
    return c.json(
      { error: "Invite the collaborator to this vault first." },
      409
    );
  }

  let body: { envelope?: any };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const marker = await readVaultMarker(c, res.target.ownerId, res.target.vault);
  const keyVersion = marker.keyVersion ?? 1;
  const envelope = body?.envelope;
  const allowedVersions = marker.rotating
    ? [keyVersion, keyVersion + 1]
    : [keyVersion];
  if (
    !isValidEnvelope(envelope, {
      ownerId: res.target.ownerId,
      vault: res.target.vault,
      recipientId: recipient.id,
    }) ||
    !allowedVersions.includes(envelope.keyVersion)
  ) {
    return c.json(
      { error: "Invalid key envelope for this vault version." },
      400
    );
  }
  const serialized = JSON.stringify(envelope);
  if (serialized.length > MAX_ENVELOPE_BYTES) {
    return c.json({ error: "Key envelope exceeds the maximum size." }, 413);
  }

  const target = res.target;
  await putStoredData(
    c,
    vaultEnvelopeStorageKey(target.ownerId, target.vault, recipient.id),
    serialized
  );
  await withVaultLock(
    `envelopes:${target.ownerId}:${target.vault}`,
    async () => {
      const idxRaw = await getStoredData(
        c,
        vaultEnvelopeIndexKey(target.ownerId, target.vault)
      );
      let ids: string[] = [];
      try {
        ids = idxRaw ? JSON.parse(idxRaw) : [];
      } catch {}
      if (!ids.includes(recipient.id)) {
        ids.push(recipient.id);
        await putStoredData(
          c,
          vaultEnvelopeIndexKey(target.ownerId, target.vault),
          JSON.stringify(ids)
        );
      }
    }
  );

  return c.json({ ok: true, keyVersion, recipient: recipientUsername });
});

app.delete("/api/vaults/:vaultName/envelope/:recipientUsername", async (c) => {
  const vaultName = c.req.param("vaultName");
  const recipientUsername = c.req.param("recipientUsername");
  if (!isValidVaultName(vaultName) || !isValidUsername(recipientUsername)) {
    return c.json({ error: "Invalid parameters." }, 400);
  }
  const res = await resolveVaultTarget(c, vaultName);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json(
      { error: "Only the vault owner can remove key envelopes." },
      403
    );
  }

  const recipientRaw = await getStoredData(
    c,
    `user:${recipientUsername.toLowerCase()}`
  );
  let recipient: any = null;
  try {
    recipient = recipientRaw ? JSON.parse(recipientRaw) : null;
  } catch {}
  if (recipient?.id) {
    await deleteVaultEnvelopeFor(
      c,
      res.target.ownerId,
      res.target.vault,
      recipient.id
    );
  }
  return c.json({ ok: true });
});

// Protocol v2: vault key rotation lifecycle
app.post("/api/vaults/:vaultName/rotation", async (c) => {
  const vaultName = c.req.param("vaultName");
  if (!isValidVaultName(vaultName)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }
  const res = await resolveVaultTarget(c, vaultName);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json(
      { error: "Only the vault owner can rotate the vault key." },
      403
    );
  }

  let body: { action?: string; keyVersion?: number };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const marker = await readVaultMarker(c, res.target.ownerId, res.target.vault);
  const currentVersion = marker.keyVersion ?? 1;
  const callerDevice = c.req.header("x-device-id") || "";
  if (!isValidDeviceId(callerDevice || undefined)) {
    return c.json(
      { error: "Valid device id is required for key rotation." },
      400
    );
  }

  if (body?.action === "begin") {
    if (
      marker.rotating &&
      marker.rotatingBy &&
      marker.rotatingBy !== callerDevice
    ) {
      return c.json(
        {
          error:
            "A re-key is already running on another device. Wait for it to finish or cancel it there.",
        },
        409
      );
    }
    const next = await writeVaultMarker(
      c,
      res.target.ownerId,
      res.target.vault,
      {
        rotating: true,
        rotatingBy: callerDevice,
        rotationStartedAt: marker.rotationStartedAt ?? Date.now(),
        keyVersion: currentVersion,
      }
    );
    return c.json({
      ok: true,
      keyVersion: next.keyVersion,
      rotating: true,
      rotatingBy: next.rotatingBy,
    });
  }
  if (body?.action === "abort") {
    if (
      marker.rotating &&
      marker.rotatingBy &&
      marker.rotatingBy !== callerDevice
    ) {
      // Safety valve: if the starting device is gone, any device may release
      // the lock after the rotation has been abandoned for a while.
      const startedAt = marker.rotationStartedAt ?? 0;
      const stale = startedAt > 0 && Date.now() - startedAt > 30 * 60 * 1000;
      if (!stale) {
        return c.json(
          { error: "Only the device that started the re-key can cancel it." },
          403
        );
      }
    }
    const next = await writeVaultMarker(
      c,
      res.target.ownerId,
      res.target.vault,
      {
        rotating: false,
        rotatingBy: undefined,
        rotationStartedAt: undefined,
      }
    );
    return c.json({
      ok: true,
      keyVersion: next.keyVersion ?? currentVersion,
      rotating: false,
    });
  }
  if (body?.action === "commit") {
    if (
      marker.rotating &&
      marker.rotatingBy &&
      marker.rotatingBy !== callerDevice
    ) {
      return c.json(
        { error: "Only the device that started the re-key can finish it." },
        403
      );
    }
    const targetVersion = Number(body?.keyVersion);
    if (!Number.isFinite(targetVersion) || targetVersion <= currentVersion) {
      return c.json(
        { error: "keyVersion must be greater than the current version." },
        400
      );
    }
    const next = await writeVaultMarker(
      c,
      res.target.ownerId,
      res.target.vault,
      {
        rotating: false,
        rotatingBy: undefined,
        rotationStartedAt: undefined,
        keyVersion: targetVersion,
      }
    );
    return c.json({ ok: true, keyVersion: next.keyVersion, rotating: false });
  }
  return c.json({ error: "Unknown rotation action." }, 400);
});

// Protocol v2: purge old history/trash during rotation (they are encrypted with
// the previous key and must not survive a re-key).
app.post("/api/vaults/:vaultName/purge", async (c) => {
  const vaultName = c.req.param("vaultName");
  if (!isValidVaultName(vaultName)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }
  const res = await resolveVaultTarget(c, vaultName);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json(
      { error: "Only the vault owner can purge vault derivatives." },
      403
    );
  }
  const marker = await readVaultMarker(c, res.target.ownerId, res.target.vault);
  if (!marker.rotating) {
    return c.json(
      { error: "Purge is only allowed while the vault is being re-keyed." },
      409
    );
  }

  for (const prefix of [
    `users/${res.target.ownerId}/history/${res.target.vault}/`,
    `users/${res.target.ownerId}/trash/${res.target.vault}/`,
  ]) {
    let cursor: string | undefined = undefined;
    let truncated = true;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({
        prefix,
        cursor,
        limit: 500,
      });
      const keys = list.objects.map((o) => o.key);
      if (keys.length > 0) await c.env.CLOUDSYNC_BUCKET.delete(keys);
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
  }
  return c.json({ ok: true });
});

// Bulk-delete old encrypted objects during a re-key. One request, no change-feed
// writes: the old names are dead once the new key is committed, and per-object
// change records made large rotations fail under metadata contention.
app.post("/api/vaults/:vaultName/purge-objects", async (c) => {
  const vaultName = c.req.param("vaultName");
  if (!isValidVaultName(vaultName)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }
  const res = await resolveVaultTarget(c, vaultName);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json({ error: "Only the vault owner can purge objects." }, 403);
  }
  const marker = await readVaultMarker(c, res.target.ownerId, res.target.vault);
  if (!marker.rotating) {
    return c.json(
      {
        error:
          "Object purge is only allowed while the vault is being re-keyed.",
      },
      409
    );
  }

  let body: { keys?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }
  const keys = Array.isArray(body?.keys) ? (body.keys as unknown[]) : [];
  if (keys.length > 500) {
    return c.json({ error: "Too many keys in one request." }, 400);
  }
  const prefix = `users/${res.target.ownerId}/vaults/${res.target.vault}/`;
  const valid: string[] = [];
  for (const key of keys) {
    if (
      typeof key !== "string" ||
      !isValidFileKey(key) ||
      key.startsWith(".cloudsync")
    ) {
      continue;
    }
    valid.push(prefix + key);
  }
  for (let i = 0; i < valid.length; i += 100) {
    await c.env.CLOUDSYNC_BUCKET.delete(valid.slice(i, i + 100));
  }
  return c.json({ ok: true, deleted: valid.length });
});

// File sync endpoints
app.get("/api/sync/walk", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  const prefix = `users/${ownerId}/vaults/${targetVault}/`;
  const files: any[] = [];
  let cursor: string | undefined = undefined;
  let truncated = true;

  while (truncated) {
    const list = await c.env.CLOUDSYNC_BUCKET.list({
      prefix,
      cursor,
      limit: 1000,
    } as any);
    for (const obj of list.objects) {
      const relKey = obj.key.slice(prefix.length);
      if (relKey.startsWith(".cloudsync") || relKey === "") continue;

      const mtime = obj.customMetadata?.mtime
        ? Number.parseInt(obj.customMetadata.mtime, 10)
        : obj.uploaded.getTime();

      files.push({
        key: relKey,
        keyRaw: relKey,
        size: obj.size,
        sizeRaw: obj.size,
        mtimeCli: mtime,
        mtimeSvr: mtime,
        etag: obj.httpEtag,
      });
    }
    truncated = list.truncated;
    cursor = list.truncated ? list.cursor : undefined;
  }

  let latestRev = 0;
  try {
    const metaObj = await c.env.CLOUDSYNC_BUCKET.get(
      `users/${ownerId}/vaults/${targetVault}/.cloudsync_meta.json`
    );
    if (metaObj) {
      const meta = (await metaObj.json()) as any;
      if (meta?.revision) latestRev = meta.revision;
    }
  } catch {}

  return c.json({ ok: true, files, revision: latestRev });
});

app.get("/api/sync/changes", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  const since = Number.parseInt(c.req.query("since") || "0", 10);
  const vaultKey = `${ownerId}:${targetVault}`;

  let latestRev = 0;
  let allChanges: VaultChange[] = [];
  let metaPresences: Record<string, CachedCursor> = {};

  try {
    const metaObj = await c.env.CLOUDSYNC_BUCKET.get(
      `users/${ownerId}/vaults/${targetVault}/.cloudsync_meta.json`
    );
    if (metaObj) {
      const meta = (await metaObj.json()) as any;
      latestRev = meta?.revision || 0;
      allChanges = Array.isArray(meta?.changes) ? meta.changes : [];
      if (meta?.presences && typeof meta.presences === "object") {
        metaPresences = meta.presences;
      }
    }
  } catch {}

  const callerDeviceId = c.req.header("x-device-id") || "";
  const cursorChanges: VaultChange[] = [];
  let maxCursorRev = 0;
  const now = Date.now();

  for (const [devId, item] of Object.entries(metaPresences)) {
    if (now - item.timestamp > CURSOR_TTL_MS) {
      continue;
    }
    if (callerDeviceId && devId === callerDeviceId) {
      continue;
    }
    if (item.rev > maxCursorRev) {
      maxCursorRev = item.rev;
    }
    cursorChanges.push({
      rev: item.rev,
      key: item.key,
      action: "cursor",
      mtime: item.timestamp,
      cursor: item.cursor,
      deviceId: item.deviceId,
      deviceName: item.deviceName,
    });
  }

  const devMap = cursorCache.get(vaultKey);
  if (devMap) {
    for (const [devId, item] of devMap.entries()) {
      if (now - item.timestamp > CURSOR_TTL_MS) {
        devMap.delete(devId);
        continue;
      }
      if (callerDeviceId && devId === callerDeviceId) {
        continue;
      }
      if (!cursorChanges.some((c) => c.deviceId === devId)) {
        if (item.rev > maxCursorRev) {
          maxCursorRev = item.rev;
        }
        cursorChanges.push({
          rev: item.rev,
          key: item.key,
          action: "cursor",
          mtime: item.timestamp,
          cursor: item.cursor,
          deviceId: item.deviceId,
          deviceName: item.deviceName,
        });
      }
    }
    if (devMap.size === 0) {
      cursorCache.delete(vaultKey);
    }
  }

  if (since > 0 && latestRev <= since && cursorChanges.length === 0) {
    return c.json({
      ok: true,
      revision: Math.max(latestRev, maxCursorRev),
      fullScanNeeded: false,
      changes: [],
    });
  }

  let changes =
    since > 0 ? allChanges.filter((ch) => ch.rev > since) : allChanges;

  if (callerDeviceId) {
    changes = changes.filter(
      (ch) => ch.action !== "cursor" || ch.deviceId !== callerDeviceId
    );
  }

  if (cursorChanges.length > 0) {
    const cursorDevIds = new Set(cursorChanges.map((c) => c.deviceId));
    changes = changes.filter(
      (ch) => ch.action !== "cursor" || !cursorDevIds.has(ch.deviceId)
    );
    changes = [...cursorChanges, ...changes];
  }

  const oldestInRing =
    allChanges.length > 0 ? allChanges[allChanges.length - 1].rev : 0;
  const fullScanNeeded =
    since > 0 && allChanges.length >= 100 && since < oldestInRing;

  return c.json({
    ok: true,
    revision: Math.max(latestRev, maxCursorRev),
    fullScanNeeded,
    changes,
  });
});

app.get("/api/sync/file", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.text(
      res.error || "Invalid parameters",
      (res.status || 400) as any
    );
  if (!isValidFileKey(key)) return c.text("Invalid parameters", 400);
  const { ownerId, vault: targetVault } = res.target;

  const obj = await c.env.CLOUDSYNC_BUCKET.get(
    `users/${ownerId}/vaults/${targetVault}/${key}`
  );
  if (!obj) return c.text("File not found", 404);

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (obj.customMetadata?.mtime)
    headers.set("x-mtime", obj.customMetadata.mtime);
  if (obj.customMetadata?.ctime)
    headers.set("x-ctime", obj.customMetadata.ctime);
  if (obj.customMetadata?.integrity)
    headers.set("x-integrity", obj.customMetadata.integrity);
  headers.set("content-length", `${obj.size}`);

  return new Response(obj.body, { headers });
});

app.on("HEAD", "/api/sync/file", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.text(
      res.error || "Invalid parameters",
      (res.status || 400) as any
    );
  if (!isValidFileKey(key)) return c.text("Invalid parameters", 400);
  const { ownerId, vault: targetVault } = res.target;

  const obj = await c.env.CLOUDSYNC_BUCKET.head(
    `users/${ownerId}/vaults/${targetVault}/${key}`
  );
  if (!obj) return c.text("File not found", 404);

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (obj.customMetadata?.mtime)
    headers.set("x-mtime", obj.customMetadata.mtime);
  if (obj.customMetadata?.ctime)
    headers.set("x-ctime", obj.customMetadata.ctime);
  if (obj.customMetadata?.integrity)
    headers.set("x-integrity", obj.customMetadata.integrity);
  headers.set("content-length", `${obj.size}`);

  return new Response(null, { headers });
});

app.put("/api/sync/file", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!isValidFileKey(key))
    return c.json({ error: "Invalid parameters." }, 400);
  const notWritable = await assertVaultWritable(c, res.target);
  if (notWritable) return notWritable;
  const { ownerId, vault: targetVault } = res.target;

  const integrityHeader = c.req.header("x-integrity") || "";
  if (integrityHeader && !INTEGRITY_HEX_RE.test(integrityHeader)) {
    return c.json({ error: "Invalid integrity header." }, 400);
  }

  const declaredLength = Number(c.req.header("content-length") || "0");
  if (declaredLength > MAX_FILE_SIZE) {
    return c.json(
      { error: `File exceeds the maximum size of ${MAX_FILE_SIZE} bytes.` },
      413
    );
  }

  const r2Key = `users/${ownerId}/vaults/${targetVault}/${key}`;
  const mtime = c.req.header("x-mtime") || `${Date.now()}`;
  const ctime = c.req.header("x-ctime") || mtime;
  const contentType =
    c.req.header("content-type") || "application/octet-stream";
  const body = await c.req.raw.arrayBuffer();

  if (body.byteLength > MAX_FILE_SIZE) {
    return c.json(
      { error: `File exceeds the maximum size of ${MAX_FILE_SIZE} bytes.` },
      413
    );
  }

  let usedBytes = await getUserStorageBytes(c, ownerId);
  if (usedBytes + body.byteLength > USER_QUOTA_BYTES) {
    // The cached value may be stale; verify with a fresh listing before rejecting.
    storageCache.delete(ownerId);
    usedBytes = await getUserStorageBytes(c, ownerId);
    if (usedBytes + body.byteLength > USER_QUOTA_BYTES) {
      return c.json({ error: "Storage quota exceeded." }, 413);
    }
  }

  // Snapshot the previous content before overwriting (all files, encrypted names included).
  try {
    const existing = await c.env.CLOUDSYNC_BUCKET.get(r2Key);
    await snapshotExisting(c, ownerId, targetVault, key, existing);
  } catch {}

  const obj = await c.env.CLOUDSYNC_BUCKET.put(r2Key, body, {
    customMetadata: integrityHeader
      ? { mtime, ctime, integrity: integrityHeader }
      : { mtime, ctime },
    httpMetadata: { contentType },
  });

  const cursorLine = c.req.header("x-cursor-line");
  const cursorCh = c.req.header("x-cursor-ch");
  const deviceId = c.req.header("x-device-id") || undefined;
  if (!isValidDeviceId(deviceId)) {
    return c.json({ error: "Invalid device id." }, 400);
  }
  const deviceName = decodeDeviceName(c.req.header("x-device-name"));
  const parsedLine =
    cursorLine !== undefined ? Number.parseInt(cursorLine, 10) : undefined;
  const parsedCh =
    cursorCh !== undefined ? Number.parseInt(cursorCh, 10) : undefined;
  const cursor =
    parsedLine !== undefined &&
    parsedCh !== undefined &&
    Number.isFinite(parsedLine) &&
    Number.isFinite(parsedCh) &&
    parsedLine >= 0 &&
    parsedCh >= 0
      ? { line: parsedLine, ch: parsedCh }
      : undefined;
  const device = deviceId
    ? { deviceId, deviceName: deviceName || "Remote Device" }
    : undefined;

  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    key,
    "put",
    Number.parseInt(mtime, 10),
    body.byteLength,
    cursor,
    device
  );

  return c.json({
    ok: true,
    key,
    size: body.byteLength,
    mtime: Number.parseInt(mtime, 10),
    etag: obj?.httpEtag,
    revision: rev,
  });
});

app.put("/api/sync/cursor", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";
  const lineStr = c.req.header("x-cursor-line");
  const chStr = c.req.header("x-cursor-ch");
  const deviceId = c.req.header("x-device-id") || undefined;
  const deviceName = decodeDeviceName(c.req.header("x-device-name"));

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!isValidDeviceId(deviceId))
    return c.json({ error: "Invalid device id." }, 400);
  if (!isValidFileKey(key) || lineStr === undefined || chStr === undefined) {
    return c.json({ error: "Invalid cursor coordinates" }, 400);
  }
  const { ownerId, vault: targetVault } = res.target;

  const parsedLine = Number.parseInt(lineStr, 10);
  const parsedCh = Number.parseInt(chStr, 10);
  if (
    !Number.isFinite(parsedLine) ||
    !Number.isFinite(parsedCh) ||
    parsedLine < 0 ||
    parsedCh < 0
  ) {
    return c.json({ error: "Invalid cursor coordinates" }, 400);
  }
  const cursor = { line: parsedLine, ch: parsedCh };
  const device = deviceId
    ? { deviceId, deviceName: deviceName || "Remote Device" }
    : undefined;
  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    key,
    "cursor",
    Date.now(),
    undefined,
    cursor,
    device
  );

  return c.json({ ok: true, revision: rev });
});

app.delete("/api/sync/cursor", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const deviceId = c.req.header("x-device-id");

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!deviceId) return c.json({ error: "Missing device ID" }, 400);

  const { ownerId, vault: targetVault } = res.target;
  const vaultKey = `${ownerId}:${targetVault}`;

  // Remove from local isolate memory
  const devMap = cursorCache.get(vaultKey);
  if (devMap) {
    devMap.delete(deviceId);
    if (devMap.size === 0) {
      cursorCache.delete(vaultKey);
    }
  }

  // Broadcast a leave event through the same serialized change path.
  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    "",
    "cursor",
    Date.now(),
    undefined,
    undefined,
    { deviceId, deviceName: "" }
  );

  return c.json({ ok: true, revision: rev });
});

app.delete("/api/sync/file", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!isValidFileKey(key)) return c.json({ error: "Invalid file key." }, 400);
  const notWritable = await assertVaultWritable(c, res.target);
  if (notWritable) return notWritable;
  const { ownerId, vault: targetVault } = res.target;

  const r2Key = `users/${ownerId}/vaults/${targetVault}/${key}`;

  if (key.endsWith("/")) {
    let cursor: string | undefined = undefined;
    let truncated = true;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({
        prefix: r2Key,
        cursor,
        limit: 500,
      });
      const toDelete = list.objects.map((o) => o.key);
      if (toDelete.length > 0) await c.env.CLOUDSYNC_BUCKET.delete(toDelete);
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
  } else {
    // Copy to trash first. If the copy fails we must NOT delete the original,
    // otherwise the file is lost forever.
    try {
      const existing = await c.env.CLOUDSYNC_BUCKET.get(r2Key);
      if (existing) {
        const data = await existing.arrayBuffer();
        await c.env.CLOUDSYNC_BUCKET.put(
          `users/${ownerId}/trash/${targetVault}/${key}`,
          data,
          {
            customMetadata: {
              ...existing.customMetadata,
              deletedAt: `${Date.now()}`,
            },
          }
        );
      }
    } catch (err) {
      console.error("Failed to move file to trash, aborting delete:", err);
      return c.json(
        { error: "Failed to preserve file in cloud trash; delete aborted." },
        500
      );
    }
    cleanupTrash(c, ownerId, targetVault).catch(() => {});
  }

  await c.env.CLOUDSYNC_BUCKET.delete(r2Key);
  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    key,
    "delete",
    Date.now()
  );

  return c.json({ ok: true, revision: rev });
});

app.post("/api/sync/rename", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const notWritable = await assertVaultWritable(c, res.target);
  if (notWritable) return notWritable;
  const { ownerId, vault: targetVault } = res.target;

  let body: { from?: string; to?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  if (
    !body.from ||
    !body.to ||
    !isValidFileKey(body.from) ||
    !isValidFileKey(body.to)
  ) {
    return c.json({ error: "Invalid file paths." }, 400);
  }

  const sourceKey = `users/${ownerId}/vaults/${targetVault}/${body.from}`;
  const targetKey = `users/${ownerId}/vaults/${targetVault}/${body.to}`;

  const source = await c.env.CLOUDSYNC_BUCKET.get(sourceKey);
  if (!source) return c.json({ error: "Source not found" }, 404);

  // Preserve the target if the rename overwrites an existing object.
  try {
    const existingTarget = await c.env.CLOUDSYNC_BUCKET.get(targetKey);
    await snapshotExisting(c, ownerId, targetVault, body.to, existingTarget);
  } catch {}

  const content = await source.arrayBuffer();
  await c.env.CLOUDSYNC_BUCKET.put(targetKey, content, {
    customMetadata: source.customMetadata,
    httpMetadata: source.httpMetadata,
  });
  await c.env.CLOUDSYNC_BUCKET.delete(sourceKey);

  await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    body.from,
    "delete",
    Date.now()
  );
  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    body.to,
    "put",
    Number.parseInt(source.customMetadata?.mtime || `${Date.now()}`, 10),
    content.byteLength
  );

  return c.json({ ok: true, revision: rev });
});

// Trash recovery
app.get("/api/sync/trash", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  const prefix = `users/${ownerId}/trash/${targetVault}/`;
  const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix, limit: 200 });

  const files = list.objects.map((o) => ({
    key: o.key.slice(prefix.length),
    size: o.size,
    deletedAt: o.customMetadata?.deletedAt
      ? Number.parseInt(o.customMetadata.deletedAt, 10)
      : o.uploaded.getTime(),
  }));

  files.sort((a, b) => b.deletedAt - a.deletedAt);
  return c.json({ ok: true, files });
});

app.post("/api/sync/trash/restore", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const notWritable = await assertVaultWritable(c, res.target);
  if (notWritable) return notWritable;
  const { ownerId, vault: targetVault } = res.target;

  let body: { key?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  const key = (body?.key || "").trim();
  if (!isValidFileKey(key)) return c.json({ error: "Invalid key." }, 400);

  const trashKey = `users/${ownerId}/trash/${targetVault}/${key}`;
  const targetKey = `users/${ownerId}/vaults/${targetVault}/${key}`;

  const trashObj = await c.env.CLOUDSYNC_BUCKET.get(trashKey);
  if (!trashObj) return c.json({ error: "File not found in trash." }, 404);

  // Preserve whatever currently occupies the target path before overwriting it.
  try {
    const current = await c.env.CLOUDSYNC_BUCKET.get(targetKey);
    await snapshotExisting(c, ownerId, targetVault, key, current);
  } catch {}

  const data = await trashObj.arrayBuffer();
  const mtime = Date.now();
  const restoredMetadata: Record<string, string> = { mtime: `${mtime}` };
  if (trashObj.customMetadata?.integrity) {
    restoredMetadata.integrity = trashObj.customMetadata.integrity;
  }
  await c.env.CLOUDSYNC_BUCKET.put(targetKey, data, {
    customMetadata: restoredMetadata,
  });
  await c.env.CLOUDSYNC_BUCKET.delete(trashKey);

  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    key,
    "put",
    mtime,
    data.byteLength
  );
  return c.json({ ok: true, key, revision: rev });
});

// History versions
app.get("/api/sync/history", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!isValidFileKey(key))
    return c.json({ error: "Invalid parameters." }, 400);
  const { ownerId, vault: targetVault } = res.target;

  const prefix = `users/${ownerId}/history/${targetVault}/${key}/`;
  const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix, limit: 100 });

  const versions = list.objects.map((o) => {
    const versionId = o.key.slice(prefix.length);
    const ts = Number.parseInt(versionId, 10) || o.uploaded.getTime();
    return { versionId, timestamp: ts, size: o.size };
  });

  versions.sort((a, b) => b.timestamp - a.timestamp);
  return c.json({ ok: true, key, versions });
});

app.get("/api/sync/history/version", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const key = c.req.query("key") || "";
  const versionId = c.req.query("versionId") || "";

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (
    !isValidFileKey(key) ||
    !versionId ||
    versionId.includes("/") ||
    versionId.includes("\\") ||
    versionId.includes("..")
  ) {
    return c.json({ error: "Invalid parameters." }, 400);
  }
  const { ownerId, vault: targetVault } = res.target;

  const histKey = `users/${ownerId}/history/${targetVault}/${key}/${versionId}`;
  const obj = await c.env.CLOUDSYNC_BUCKET.get(histKey);
  if (!obj) return c.json({ error: "Historical version not found." }, 404);

  c.header(
    "Content-Type",
    obj.httpMetadata?.contentType || "application/octet-stream"
  );
  c.header("Content-Length", `${obj.size}`);
  if (obj.customMetadata?.integrity) {
    c.header("x-integrity", obj.customMetadata.integrity);
  }
  return c.body(obj.body);
});

app.post("/api/sync/history/restore", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const notWritable = await assertVaultWritable(c, res.target);
  if (notWritable) return notWritable;
  const { ownerId, vault: targetVault } = res.target;

  let body: { key?: string; versionId?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  const key = (body?.key || "").trim();
  const versionId = (body?.versionId || "").trim();
  if (
    !isValidFileKey(key) ||
    !versionId ||
    versionId.includes("/") ||
    versionId.includes("\\") ||
    versionId.includes("..")
  ) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const hist = await c.env.CLOUDSYNC_BUCKET.get(
    `users/${ownerId}/history/${targetVault}/${key}/${versionId}`
  );
  if (!hist) return c.json({ error: "Version not found." }, 404);

  // Preserve the current content before restoring an older version over it.
  try {
    const current = await c.env.CLOUDSYNC_BUCKET.get(
      `users/${ownerId}/vaults/${targetVault}/${key}`
    );
    await snapshotExisting(c, ownerId, targetVault, key, current);
  } catch {}

  const data = await hist.arrayBuffer();
  const mtime = Date.now();
  const restoredMetadata: Record<string, string> = { mtime: `${mtime}` };
  if (hist.customMetadata?.integrity) {
    restoredMetadata.integrity = hist.customMetadata.integrity;
  }
  await c.env.CLOUDSYNC_BUCKET.put(
    `users/${ownerId}/vaults/${targetVault}/${key}`,
    data,
    {
      customMetadata: restoredMetadata,
    }
  );

  const rev = await recordVaultChange(
    c.env,
    ownerId,
    targetVault,
    key,
    "put",
    mtime,
    data.byteLength
  );
  return c.json({ ok: true, key, revision: rev });
});

// Shares
app.get("/api/sync/shares", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  const raw = await getStoredData(c, `vault_shares:${ownerId}:${targetVault}`);
  const shares: string[] = raw ? JSON.parse(raw) : [];
  return c.json({
    ok: true,
    vault: targetVault,
    shares,
    isOwner: res.target.isOwner,
  });
});

app.post("/api/sync/shares", async (c) => {
  const currentUsername = c.get("username") || "";
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json(
      { error: "Only the vault owner can manage collaborators." },
      403
    );
  }
  const { ownerId, vault: targetVault } = res.target;

  let body: { inviteUsername?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  const inviteUsername = (body?.inviteUsername || "").trim();
  if (!inviteUsername || !isValidUsername(inviteUsername)) {
    return c.json({ error: "Valid username is required." }, 400);
  }
  if (inviteUsername.toLowerCase() === currentUsername.toLowerCase()) {
    return c.json({ error: "You cannot invite yourself." }, 400);
  }

  const inviteUserRaw = await getStoredData(
    c,
    `user:${inviteUsername.toLowerCase()}`
  );
  if (!inviteUserRaw)
    return c.json({ error: `User "${inviteUsername}" does not exist.` }, 404);
  const inviteUser = JSON.parse(inviteUserRaw);

  const sharesKey = `vault_shares:${ownerId}:${targetVault}`;
  const raw = await getStoredData(c, sharesKey);
  const shares: string[] = raw ? JSON.parse(raw) : [];

  if (!shares.some((u) => u.toLowerCase() === inviteUsername.toLowerCase())) {
    shares.push(inviteUsername);
    await putStoredData(c, sharesKey, JSON.stringify(shares));
  }

  // Update invitee's shared vaults reverse index
  try {
    const inviteeSharesKey = `user_shared_vaults:${inviteUser.id}`;
    const inviteeRaw = await getStoredData(c, inviteeSharesKey);
    const inviteeShares: Array<{
      vault: string;
      ownerId: string;
      ownerUsername: string;
    }> = inviteeRaw ? JSON.parse(inviteeRaw) : [];
    if (
      !inviteeShares.some(
        (s) => s.vault === targetVault && s.ownerId === ownerId
      )
    ) {
      inviteeShares.push({
        vault: targetVault,
        ownerId,
        ownerUsername: currentUsername,
      });
      await putStoredData(c, inviteeSharesKey, JSON.stringify(inviteeShares));
    }
  } catch (err) {
    console.error("Failed to update invitee shares reverse index:", err);
  }

  return c.json({
    ok: true,
    message: `Vault shared with ${inviteUsername}`,
    shares,
  });
});

app.delete("/api/sync/shares", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const username = c.req.query("username");
  if (!username) return c.json({ error: "Invalid parameters." }, 400);

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  if (!res.target.isOwner) {
    return c.json(
      { error: "Only the vault owner can manage collaborators." },
      403
    );
  }
  const { ownerId, vault: targetVault } = res.target;

  const sharesKey = `vault_shares:${ownerId}:${targetVault}`;
  const raw = await getStoredData(c, sharesKey);
  let shares: string[] = raw ? JSON.parse(raw) : [];
  shares = shares.filter((u) => u.toLowerCase() !== username.toLowerCase());
  await putStoredData(c, sharesKey, JSON.stringify(shares));

  // Update invitee's shared vaults reverse index
  try {
    const targetUserRaw = await getStoredData(
      c,
      `user:${username.toLowerCase()}`
    );
    if (targetUserRaw) {
      const targetUser = JSON.parse(targetUserRaw);
      const inviteeSharesKey = `user_shared_vaults:${targetUser.id}`;
      const inviteeRaw = await getStoredData(c, inviteeSharesKey);
      if (inviteeRaw) {
        let inviteeShares: Array<{
          vault: string;
          ownerId: string;
          ownerUsername: string;
        }> = JSON.parse(inviteeRaw);
        inviteeShares = inviteeShares.filter(
          (s) => !(s.vault === targetVault && s.ownerId === ownerId)
        );
        await putStoredData(c, inviteeSharesKey, JSON.stringify(inviteeShares));
      }
      if (targetUser?.id) {
        await deleteVaultEnvelopeFor(c, ownerId, targetVault, targetUser.id);
      }
    }
  } catch (err) {
    console.error("Failed to remove invitee shares reverse index:", err);
  }

  return c.json({ ok: true, shares });
});

// Devices
app.get("/api/sync/devices", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  try {
    const raw = await getStoredData(
      c,
      `vault_devices:${ownerId}:${targetVault}`
    );
    const devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    return c.json({ devices });
  } catch (err: any) {
    return c.json({ devices: [], error: err?.message });
  }
});

app.put("/api/sync/devices", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  if (
    !body?.deviceId ||
    typeof body.deviceId !== "string" ||
    !/^[a-zA-Z0-9._-]{1,64}$/.test(body.deviceId)
  ) {
    return c.json({ error: "Invalid deviceId" }, 400);
  }

  const devicesKey = `vault_devices:${ownerId}:${targetVault}`;
  try {
    const raw = await getStoredData(c, devicesKey);
    const devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    const idx = devices.findIndex((d) => d.deviceId === body.deviceId);
    const updated: DeviceInfo = {
      deviceId: body.deviceId,
      deviceName: String(body.deviceName || "Unnamed Device").slice(0, 64),
      platform:
        body.platform === "desktop" || body.platform === "mobile"
          ? body.platform
          : "unknown",
      lastActive: Date.now(),
      lastBackup:
        body.lastBackup ?? (idx >= 0 ? devices[idx].lastBackup : undefined),
      fileCount:
        body.fileCount ?? (idx >= 0 ? devices[idx].fileCount : undefined),
    };

    if (idx >= 0) devices[idx] = updated;
    else devices.push(updated);

    await putStoredData(c, devicesKey, JSON.stringify(devices));
    return c.json({ ok: true, device: updated });
  } catch (err: any) {
    return c.json({ error: err?.message }, 500);
  }
});

app.delete("/api/sync/devices/:deviceId", async (c) => {
  const vault = c.req.query("vault") || "default";
  const owner = c.req.query("owner");
  const deviceId = c.req.param("deviceId");

  if (!deviceId) return c.json({ error: "Invalid parameters." }, 400);

  const res = await resolveVaultTarget(c, vault, owner);
  if (res.error || !res.target)
    return c.json({ error: res.error }, (res.status || 400) as any);
  const { ownerId, vault: targetVault } = res.target;

  const devicesKey = `vault_devices:${ownerId}:${targetVault}`;
  try {
    const raw = await getStoredData(c, devicesKey);
    let devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    devices = devices.filter((d) => d.deviceId !== deviceId);
    await putStoredData(c, devicesKey, JSON.stringify(devices));
    return c.json({ ok: true });
  } catch (err: any) {
    return c.json({ error: err?.message }, 500);
  }
});

export default app;
