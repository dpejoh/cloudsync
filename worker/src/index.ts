import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  CLOUDSYNC_BUCKET: R2Bucket;
  CLOUDSYNC_KV?: KVNamespace;
  JWT_SECRET?: string;
  WORKER_MODE?: string; // "single" | "multi"
  SINGLE_USER_PASSWORD?: string;
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

// In-memory caches for ephemeral cursor updates and storage calculations
const cursorCache = new Map<string, { key: string; cursor: { line: number; ch: number }; rev: number }>();
const storageCache = new Map<string, { bytes: number; timestamp: number }>();

app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "no-referrer");
});

app.onError((err, c) => {
  console.error("Worker unhandled error:", err);
  return c.json({ error: err.message || "Internal server error" }, 500);
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
    ],
    exposeHeaders: [
      "Content-Length",
      "x-mtime",
      "x-ctime",
      "x-cursor-line",
      "x-cursor-ch",
      "ETag",
    ],
  })
);

// Helpers
function getJwtSecret(c: any): string {
  return c.env.JWT_SECRET || "cloudsync-secret-change-me";
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return base64UrlEncode(binary);
}

function base64UrlDecode(str: string): string {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
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

async function signJwt(payload: Record<string, any>, secret: string): Promise<string> {
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

async function verifyJwt(token: string, secret: string): Promise<Record<string, any> | null> {
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

    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(`${headerB64}.${payloadB64}`));
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
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(verifier.toLowerCase()));
  const bytes = new Uint8Array(sig);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

async function verifyTotpCode(secretBase32: string, code: string): Promise<boolean> {
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

async function putStoredData(c: any, key: string, value: string): Promise<void> {
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
      console.warn("KV put quota limit exceeded, securely using R2 storage:", e);
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

const authRateLimitMap = new Map<string, { count: number; resetTime: number }>();
function checkAuthRateLimit(clientIp: string, limit = 20, windowMs = 60_000): boolean {
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

async function recordVaultChange(
  env: Bindings,
  userId: string,
  vault: string,
  key: string,
  action: "put" | "delete" | "cursor",
  mtime: number,
  size?: number,
  cursor?: { line: number; ch: number }
): Promise<number> {
  const rev = getNextRevision();
  const vaultKey = `${userId}:${vault}`;

  // Keep cursor presence in memory to avoid storage writes
  if (action === "cursor" && cursor) {
    cursorCache.set(vaultKey, { key, cursor, rev });
    return rev;
  }
  if (cursor) {
    cursorCache.set(vaultKey, { key, cursor, rev });
  }

  const metaKey = `users/${userId}/vaults/${vault}/.cloudsync_meta.json`;

  try {
    let meta: { revision: number; changes: VaultChange[] } = {
      revision: rev,
      changes: [],
    };

    const existing = await env.CLOUDSYNC_BUCKET.get(metaKey);
    if (existing) {
      try {
        const parsed = (await existing.json()) as any;
        if (parsed?.changes && Array.isArray(parsed.changes)) {
          meta.changes = parsed.changes;
        }
      } catch {}
    }

    meta.revision = rev;
    meta.changes.unshift({ rev, key, action, mtime, size, cursor });
    if (meta.changes.length > 100) {
      meta.changes = meta.changes.slice(0, 100);
    }

    await env.CLOUDSYNC_BUCKET.put(metaKey, JSON.stringify(meta), {
      httpMetadata: { contentType: "application/json" },
      customMetadata: { revision: `${rev}` },
    });

    storageCache.delete(userId);
  } catch (err) {
    console.error("Failed to record vault change:", err);
  }

  return rev;
}

// Info & health
app.get("/", (c) => {
  return c.json({
    status: "ok",
    service: "CloudSync Edge Worker",
    version: "2.1.0",
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
    version: "2.1.0",
    mode,
    requiresSetup: mode === "single" && !hasPassword,
  });
});

// Auth endpoints
app.post("/api/auth/single-login", async (c) => {
  const clientIp = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "direct";
  if (!checkAuthRateLimit(clientIp)) {
    return c.json({ error: "Too many authentication attempts. Please try again in a minute." }, 429);
  }

  let body: { verifier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const verifier = (body?.verifier || "").trim();
  if (!verifier || !isValidHexHash(verifier)) {
    return c.json({ error: "Valid 64-character password verifier required." }, 400);
  }

  const secret = getJwtSecret(c);
  const hashed = await hashVerifier(verifier, secret);

  let stored = await getStoredData(c, "single:verifier");
  if (!stored) {
    await putStoredData(c, "single:verifier", hashed);
    stored = hashed;
  }
  if (stored !== hashed && stored !== verifier.toLowerCase()) {
    return c.json({ error: "Invalid master password." }, 401);
  }

  const token = await signJwt(
    { sub: "default", username: "Owner", exp: Math.floor(Date.now() / 1000) + 86400 * 180 },
    secret
  );

  return c.json({ ok: true, token, user: { id: "default", username: "Owner" } });
});

app.post("/api/auth/register", async (c) => {
  const clientIp = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "direct";
  if (!checkAuthRateLimit(clientIp)) {
    return c.json({ error: "Too many registration attempts. Please try again in a minute." }, 429);
  }

  let body: {
    username?: string;
    verifier?: string;
    recoveryVerifier?: string;
    totpSecret?: string;
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

  if (!username || !verifier) {
    return c.json({ error: "Username and password verifier are required." }, 400);
  }
  if (!isValidUsername(username) || !isValidHexHash(verifier)) {
    return c.json({ error: "Invalid username or verifier format." }, 400);
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
    verifier: await hashVerifier(verifier, secret),
    recoveryVerifier: recoveryVerifier ? await hashVerifier(recoveryVerifier, secret) : undefined,
    totpSecret: totpSecret || undefined,
    created: Date.now(),
  };

  await putStoredData(c, userKey, JSON.stringify(userData));

  const token = await signJwt(
    { sub: userId, username, exp: Math.floor(Date.now() / 1000) + 86400 * 180 },
    secret
  );

  return c.json({ ok: true, token, user: { id: userId, username } });
});

app.post("/api/auth/login", async (c) => {
  const clientIp = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "direct";
  if (!checkAuthRateLimit(clientIp)) {
    return c.json({ error: "Too many login attempts. Please try again in a minute." }, 429);
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
    return c.json({ error: "Username and password verifier are required." }, 400);
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

  const token = await signJwt(
    { sub: user.id, username: user.username, exp: Math.floor(Date.now() / 1000) + 86400 * 180 },
    secret
  );

  return c.json({ ok: true, token, user: { id: user.id, username: user.username } });
});

app.post("/api/auth/recover", async (c) => {
  let body: { username?: string; recoveryVerifier?: string; newVerifier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const username = (body?.username || "").trim();
  const recoveryVerifier = (body?.recoveryVerifier || "").trim();
  const newVerifier = (body?.newVerifier || "").trim();

  if (!username || !recoveryVerifier || !newVerifier) {
    return c.json({ error: "Username, recovery code, and new password are required." }, 400);
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

  if (!user || !user.recoveryVerifier) {
    return c.json({ error: "Invalid recovery key or user not found." }, 401);
  }

  const hashedRecovery = await hashVerifier(recoveryVerifier, secret);
  if (user.recoveryVerifier !== hashedRecovery && user.recoveryVerifier !== recoveryVerifier.toLowerCase()) {
    return c.json({ error: "Invalid recovery key." }, 401);
  }

  user.verifier = await hashVerifier(newVerifier, secret);
  await putStoredData(c, userKey, JSON.stringify(user));

  const token = await signJwt(
    { sub: user.id, username: user.username, exp: Math.floor(Date.now() / 1000) + 86400 * 180 },
    secret
  );

  return c.json({ ok: true, token, user: { id: user.id, username: user.username } });
});

app.get("/api/auth/verify-token", async (c) => {
  const auth = c.req.header("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return c.json({ valid: false }, 401);

  const secret = getJwtSecret(c);
  const payload = await verifyJwt(match[1], secret);
  if (!payload) return c.json({ valid: false }, 401);

  return c.json({ valid: true, userId: payload.sub, username: payload.username });
});

// Authenticated route guard
app.use("/api/*", async (c, next) => {
  const path = c.req.path;
  if (path.startsWith("/api/auth/") || path === "/api/info") {
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

  c.set("userId", payload.sub);
  c.set("username", payload.username || "User");
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
      const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix: `users/${userId}/`, cursor, limit: 1000 });
      for (const obj of list.objects) storageUsedBytes += obj.size;
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
    storageCache.set(userId, { bytes: storageUsedBytes, timestamp: Date.now() });
  }

  let has2FA = false;
  if (username && username !== "Owner") {
    const raw = await getStoredData(c, `user:${username.toLowerCase()}`);
    if (raw) {
      try {
        const u = JSON.parse(raw);
        has2FA = Boolean(u.totpSecret);
      } catch {}
    }
  }

  return c.json({
    ok: true,
    userId,
    username,
    has2FA,
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
  if (user.verifier !== oldHashed && user.verifier !== oldVerifier.toLowerCase()) {
    return c.json({ error: "Incorrect current password." }, 401);
  }

  user.verifier = await hashVerifier(newVerifier, secret);
  await putStoredData(c, userKey, JSON.stringify(user));

  return c.json({ ok: true, message: "Password updated successfully." });
});

// Vault management
app.get("/api/vaults", async (c) => {
  const userId = c.get("userId");
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

  const vaults = await Promise.all(
    Array.from(vaultNamesSet).map(async (name) => {
      let revision = 0;
      try {
        const metaObj = await c.env.CLOUDSYNC_BUCKET.get(`users/${userId}/vaults/${name}/.cloudsync_meta.json`);
        if (metaObj) {
          const meta = (await metaObj.json()) as any;
          if (meta?.revision) revision = meta.revision;
        }
      } catch {}
      return { name, revision };
    })
  );

  return c.json({ ok: true, vaults });
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
    JSON.stringify({ created: now, name }),
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

  const prefixes = [
    `users/${userId}/vaults/${vaultName}/`,
    `users/${userId}/history/${vaultName}/`,
    `users/${userId}/trash/${vaultName}/`,
  ];

  for (const prefix of prefixes) {
    let truncated = true;
    let cursor: string | undefined = undefined;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix, cursor, limit: 500 });
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

// File sync endpoints
app.get("/api/sync/walk", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  const prefix = `users/${userId}/vaults/${vault}/`;
  const files: any[] = [];
  let cursor: string | undefined = undefined;
  let truncated = true;

  while (truncated) {
    const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix, cursor, limit: 1000 } as any);
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
    const metaObj = await c.env.CLOUDSYNC_BUCKET.get(`users/${userId}/vaults/${vault}/.cloudsync_meta.json`);
    if (metaObj) {
      const meta = (await metaObj.json()) as any;
      if (meta?.revision) latestRev = meta.revision;
    }
  } catch {}

  return c.json({ ok: true, files, revision: latestRev });
});

app.get("/api/sync/changes", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  const since = Number.parseInt(c.req.query("since") || "0", 10);
  const vaultKey = `${userId}:${vault}`;

  let latestRev = 0;
  let allChanges: VaultChange[] = [];

  try {
    const metaObj = await c.env.CLOUDSYNC_BUCKET.get(`users/${userId}/vaults/${vault}/.cloudsync_meta.json`);
    if (metaObj) {
      const meta = (await metaObj.json()) as any;
      latestRev = meta?.revision || 0;
      allChanges = Array.isArray(meta?.changes) ? meta.changes : [];
    }
  } catch {}

  const memCursor = cursorCache.get(vaultKey);
  const memCursorMatches = memCursor && memCursor.rev > since;

  if (since > 0 && latestRev <= since && !memCursorMatches) {
    return c.json({ ok: true, revision: latestRev, fullScanNeeded: false, changes: [] });
  }

  let changes = since > 0 ? allChanges.filter((ch) => ch.rev > since) : allChanges;

  if (memCursorMatches && memCursor) {
    changes = [
      {
        rev: memCursor.rev,
        key: memCursor.key,
        action: "cursor",
        mtime: memCursor.rev,
        cursor: memCursor.cursor,
      },
      ...changes,
    ];
  }

  const oldestInRing = allChanges.length > 0 ? allChanges[allChanges.length - 1].rev : 0;
  const fullScanNeeded = since > 0 && allChanges.length >= 100 && since < oldestInRing;

  return c.json({
    ok: true,
    revision: Math.max(latestRev, memCursor?.rev || 0),
    fullScanNeeded,
    changes,
  });
});

app.get("/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault) || !isValidFileKey(key)) {
    return c.text("Invalid parameters", 400);
  }

  const obj = await c.env.CLOUDSYNC_BUCKET.get(`users/${userId}/vaults/${vault}/${key}`);
  if (!obj) return c.text("File not found", 404);

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (obj.customMetadata?.mtime) headers.set("x-mtime", obj.customMetadata.mtime);
  if (obj.customMetadata?.ctime) headers.set("x-ctime", obj.customMetadata.ctime);
  headers.set("content-length", `${obj.size}`);

  return new Response(obj.body, { headers });
});

app.on("HEAD", "/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault) || !isValidFileKey(key)) {
    return c.text("Invalid parameters", 400);
  }

  const obj = await c.env.CLOUDSYNC_BUCKET.head(`users/${userId}/vaults/${vault}/${key}`);
  if (!obj) return c.text("File not found", 404);

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (obj.customMetadata?.mtime) headers.set("x-mtime", obj.customMetadata.mtime);
  if (obj.customMetadata?.ctime) headers.set("x-ctime", obj.customMetadata.ctime);
  headers.set("content-length", `${obj.size}`);

  return new Response(null, { headers });
});

app.put("/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault) || !isValidFileKey(key)) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;
  const mtime = c.req.header("x-mtime") || `${Date.now()}`;
  const ctime = c.req.header("x-ctime") || mtime;
  const contentType = c.req.header("content-type") || "application/octet-stream";
  const body = await c.req.raw.arrayBuffer();

  // Snapshot note history for text files under 2MB
  try {
    const isDoc = /\.(md|markdown|canvas|txt|json|css|js|csv|tsv|yaml|yml)$/i.test(key);
    if (isDoc) {
      const existing = await c.env.CLOUDSYNC_BUCKET.get(r2Key);
      if (existing && existing.size > 0 && existing.size <= 2 * 1024 * 1024) {
        const histData = await existing.arrayBuffer();
        const existingMtime = existing.customMetadata?.mtime || `${Date.now()}`;
        await c.env.CLOUDSYNC_BUCKET.put(
          `users/${userId}/history/${vault}/${key}/${existingMtime}`,
          histData,
          { customMetadata: { mtime: existingMtime, size: `${existing.size}` } }
        );
      }
    }
  } catch {}

  const obj = await c.env.CLOUDSYNC_BUCKET.put(r2Key, body, {
    customMetadata: { mtime, ctime },
    httpMetadata: { contentType },
  });

  const cursorLine = c.req.header("x-cursor-line");
  const cursorCh = c.req.header("x-cursor-ch");
  const cursor =
    cursorLine !== undefined && cursorCh !== undefined
      ? { line: Number.parseInt(cursorLine, 10), ch: Number.parseInt(cursorCh, 10) }
      : undefined;

  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    key,
    "put",
    Number.parseInt(mtime, 10),
    body.byteLength,
    cursor
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
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";
  const lineStr = c.req.header("x-cursor-line");
  const chStr = c.req.header("x-cursor-ch");

  if (!isValidVaultName(vault) || !isValidFileKey(key) || lineStr === undefined || chStr === undefined) {
    return c.json({ error: "Invalid cursor coordinates" }, 400);
  }

  const cursor = { line: Number.parseInt(lineStr, 10), ch: Number.parseInt(chStr, 10) };
  const rev = await recordVaultChange(c.env, userId, vault, key, "cursor", Date.now(), undefined, cursor);

  return c.json({ ok: true, revision: rev });
});

app.delete("/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault) || !isValidFileKey(key)) {
    return c.json({ error: "Invalid file key." }, 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;

  if (key.endsWith("/")) {
    let cursor: string | undefined = undefined;
    let truncated = true;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix: r2Key, cursor, limit: 500 });
      const toDelete = list.objects.map((o) => o.key);
      if (toDelete.length > 0) await c.env.CLOUDSYNC_BUCKET.delete(toDelete);
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
  } else {
    // Preserve in trash
    try {
      const existing = await c.env.CLOUDSYNC_BUCKET.get(r2Key);
      if (existing) {
        const data = await existing.arrayBuffer();
        await c.env.CLOUDSYNC_BUCKET.put(`users/${userId}/trash/${vault}/${key}`, data, {
          customMetadata: { ...existing.customMetadata, deletedAt: `${Date.now()}` },
        });
      }
    } catch {}
  }

  await c.env.CLOUDSYNC_BUCKET.delete(r2Key);
  const rev = await recordVaultChange(c.env, userId, vault, key, "delete", Date.now());

  return c.json({ ok: true, revision: rev });
});

app.post("/api/sync/rename", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  let body: { from?: string; to?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  if (!body.from || !body.to || !isValidFileKey(body.from) || !isValidFileKey(body.to)) {
    return c.json({ error: "Invalid file paths." }, 400);
  }

  const sourceKey = `users/${userId}/vaults/${vault}/${body.from}`;
  const targetKey = `users/${userId}/vaults/${vault}/${body.to}`;

  const source = await c.env.CLOUDSYNC_BUCKET.get(sourceKey);
  if (!source) return c.json({ error: "Source not found" }, 404);

  const content = await source.arrayBuffer();
  await c.env.CLOUDSYNC_BUCKET.put(targetKey, content, {
    customMetadata: source.customMetadata,
    httpMetadata: source.httpMetadata,
  });
  await c.env.CLOUDSYNC_BUCKET.delete(sourceKey);

  await recordVaultChange(c.env, userId, vault, body.from, "delete", Date.now());
  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    body.to,
    "put",
    Number.parseInt(source.customMetadata?.mtime || `${Date.now()}`, 10),
    content.byteLength
  );

  return c.json({ ok: true, revision: rev });
});

// Trash recovery
app.get("/api/sync/trash", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  const prefix = `users/${userId}/trash/${vault}/`;
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
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  let body: { key?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  const key = (body?.key || "").trim();
  if (!isValidFileKey(key)) return c.json({ error: "Invalid key." }, 400);

  const trashKey = `users/${userId}/trash/${vault}/${key}`;
  const targetKey = `users/${userId}/vaults/${vault}/${key}`;

  const trashObj = await c.env.CLOUDSYNC_BUCKET.get(trashKey);
  if (!trashObj) return c.json({ error: "File not found in trash." }, 404);

  const data = await trashObj.arrayBuffer();
  const mtime = Date.now();
  await c.env.CLOUDSYNC_BUCKET.put(targetKey, data, {
    customMetadata: { mtime: `${mtime}` },
  });
  await c.env.CLOUDSYNC_BUCKET.delete(trashKey);

  const rev = await recordVaultChange(c.env, userId, vault, key, "put", mtime, data.byteLength);
  return c.json({ ok: true, key, revision: rev });
});

// History versions
app.get("/api/sync/history", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault) || !isValidFileKey(key)) return c.json({ error: "Invalid parameters." }, 400);

  const prefix = `users/${userId}/history/${vault}/${key}/`;
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
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";
  const versionId = c.req.query("versionId") || "";

  if (!isValidVaultName(vault) || !isValidFileKey(key) || !versionId) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const histKey = `users/${userId}/history/${vault}/${key}/${versionId}`;
  const obj = await c.env.CLOUDSYNC_BUCKET.get(histKey);
  if (!obj) return c.json({ error: "Historical version not found." }, 404);

  c.header("Content-Type", obj.httpMetadata?.contentType || "application/octet-stream");
  c.header("Content-Length", `${obj.size}`);
  return c.body(obj.body);
});

app.post("/api/sync/history/restore", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";

  let body: { key?: string; versionId?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  const key = (body?.key || "").trim();
  const versionId = (body?.versionId || "").trim();
  if (!isValidVaultName(vault) || !isValidFileKey(key) || !versionId) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const hist = await c.env.CLOUDSYNC_BUCKET.get(`users/${userId}/history/${vault}/${key}/${versionId}`);
  if (!hist) return c.json({ error: "Version not found." }, 404);

  const data = await hist.arrayBuffer();
  const mtime = Date.now();
  await c.env.CLOUDSYNC_BUCKET.put(`users/${userId}/vaults/${vault}/${key}`, data, {
    customMetadata: { mtime: `${mtime}` },
  });

  const rev = await recordVaultChange(c.env, userId, vault, key, "put", mtime, data.byteLength);
  return c.json({ ok: true, key, revision: rev });
});

// Shares
app.get("/api/sync/shares", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  const raw = await getStoredData(c, `vault_shares:${userId}:${vault}`);
  const shares: string[] = raw ? JSON.parse(raw) : [];
  return c.json({ ok: true, vault, shares });
});

app.post("/api/sync/shares", async (c) => {
  const userId = c.get("userId");
  const currentUsername = c.get("username");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

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

  const inviteUser = await getStoredData(c, `user:${inviteUsername.toLowerCase()}`);
  if (!inviteUser) return c.json({ error: `User "${inviteUsername}" does not exist.` }, 404);

  const sharesKey = `vault_shares:${userId}:${vault}`;
  const raw = await getStoredData(c, sharesKey);
  const shares: string[] = raw ? JSON.parse(raw) : [];

  if (!shares.some((u) => u.toLowerCase() === inviteUsername.toLowerCase())) {
    shares.push(inviteUsername);
    await putStoredData(c, sharesKey, JSON.stringify(shares));
  }

  return c.json({ ok: true, message: `Vault shared with ${inviteUsername}`, shares });
});

app.delete("/api/sync/shares", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const username = c.req.query("username");
  if (!isValidVaultName(vault) || !username) return c.json({ error: "Invalid parameters." }, 400);

  const sharesKey = `vault_shares:${userId}:${vault}`;
  const raw = await getStoredData(c, sharesKey);
  let shares: string[] = raw ? JSON.parse(raw) : [];
  shares = shares.filter((u) => u.toLowerCase() !== username.toLowerCase());
  await putStoredData(c, sharesKey, JSON.stringify(shares));

  return c.json({ ok: true, shares });
});

// Devices
app.get("/api/sync/devices", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  try {
    const raw = await getStoredData(c, `vault_devices:${userId}:${vault}`);
    const devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    return c.json({ devices });
  } catch (err: any) {
    return c.json({ devices: [], error: err?.message });
  }
});

app.put("/api/sync/devices", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  if (!isValidVaultName(vault)) return c.json({ error: "Invalid vault." }, 400);

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON." }, 400);
  }

  if (!body?.deviceId || typeof body.deviceId !== "string" || !/^[a-zA-Z0-9._-]{1,64}$/.test(body.deviceId)) {
    return c.json({ error: "Invalid deviceId" }, 400);
  }

  const devicesKey = `vault_devices:${userId}:${vault}`;
  try {
    const raw = await getStoredData(c, devicesKey);
    let devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    const idx = devices.findIndex((d) => d.deviceId === body.deviceId);
    const updated: DeviceInfo = {
      deviceId: body.deviceId,
      deviceName: String(body.deviceName || "Unnamed Device").slice(0, 64),
      platform: body.platform === "desktop" || body.platform === "mobile" ? body.platform : "unknown",
      lastActive: Date.now(),
      lastBackup: body.lastBackup ?? (idx >= 0 ? devices[idx].lastBackup : undefined),
      fileCount: body.fileCount ?? (idx >= 0 ? devices[idx].fileCount : undefined),
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
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const deviceId = c.req.param("deviceId");

  if (!isValidVaultName(vault) || !deviceId) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const devicesKey = `vault_devices:${userId}:${vault}`;
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
