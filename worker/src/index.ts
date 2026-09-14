import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  CLOUDSYNC_BUCKET: R2Bucket;
  CLOUDSYNC_KV: KVNamespace;
  JWT_SECRET?: string;
  WORKER_MODE?: string; // "single" | "multi"
  SINGLE_USER_PASSWORD?: string;
};

type Variables = {
  userId: string;
  username: string;
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Enable CORS for Obsidian desktop and web clients
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

// Health check and service info
app.get("/", (c) => {
  return c.json({
    status: "ok",
    service: "CloudSync Edge Worker",
    version: "2.0.0",
    mode: c.env.WORKER_MODE === "single" ? "single" : "multi",
  });
});

app.get("/api/info", async (c) => {
  const mode = c.env.WORKER_MODE === "single" ? "single" : "multi";
  let hasPassword = true;
  if (mode === "single") {
    if (c.env.SINGLE_USER_PASSWORD) {
      hasPassword = true;
    } else if (c.env.CLOUDSYNC_KV) {
      const stored = await c.env.CLOUDSYNC_KV.get("single:verifier");
      hasPassword = !!stored;
    } else {
      hasPassword = false;
    }
  }
  return c.json({
    status: "ok",
    service: "CloudSync",
    version: "2.0.0",
    mode,
    requiresSetup: mode === "single" && !hasPassword,
  });
});

// =============================================================================
// JWT & TOTP Web Crypto Helpers
// =============================================================================
function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return base64UrlEncode(binary);
}

function base64UrlDecode(str: string): string {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}

async function signJwt(
  payload: Record<string, any>,
  secret: string
): Promise<string> {
  const enc = new TextEncoder();
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const message = `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signature));

  return `${message}.${encodedSignature}`;
}

async function verifyJwt(
  token: string,
  secret: string
): Promise<Record<string, any> | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const message = `${headerB64}.${payloadB64}`;
    const enc = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const sigStr = base64UrlDecode(signatureB64);
    const sigBytes = new Uint8Array(sigStr.length);
    for (let i = 0; i < sigStr.length; i++) sigBytes[i] = sigStr.charCodeAt(i);

    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      enc.encode(message)
    );

    if (!isValid) return null;

    const payload = JSON.parse(base64UrlDecode(payloadB64));
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return null; // Expired
    }

    return payload;
  } catch {
    return null;
  }
}

// RFC 6238 Base32 & TOTP Verification Helpers
function base32Decode(str: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleanStr = str.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const val = alphabet.indexOf(cleanStr[i]);
    if (val === -1) continue;
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function generateTotpCode(
  secretBase32: string,
  counter: number
): Promise<string> {
  const keyBytes = base32Decode(secretBase32);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, counterBuffer);
  const hash = new Uint8Array(signature);
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  return (binary % 1000000).toString().padStart(6, "0");
}

async function verifyTotpCode(
  secretBase32: string,
  userCode: string
): Promise<boolean> {
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  const cleanCode = userCode.trim();
  for (let step = currentStep - 1; step <= currentStep + 1; step++) {
    const validCode = await generateTotpCode(secretBase32, step);
    if (validCode === cleanCode) {
      return true;
    }
  }
  return false;
}

// =============================================================================
// AUTH ROUTES
// =============================================================================

// 1. Single-User Mode Login / Unlock
app.post("/api/auth/single-login", async (c) => {
  const body = await c.req.json<{ verifier?: string }>();
  const verifier = (body.verifier || "").trim();
  if (!verifier) {
    return c.json({ error: "Password verifier is required." }, 400);
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";

  if (c.env.CLOUDSYNC_KV) {
    let stored = await c.env.CLOUDSYNC_KV.get("single:verifier");
    if (!stored) {
      // First setup: initialize single-user password verifier
      await c.env.CLOUDSYNC_KV.put("single:verifier", verifier);
      stored = verifier;
    }
    if (stored !== verifier) {
      return c.json({ error: "Invalid master password." }, 401);
    }
  }

  const token = await signJwt(
    {
      sub: "default",
      username: "Owner",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 180, // 180 days
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: "default", username: "Owner" },
  });
});

// 2. Multi-User: Register a new user
app.post("/api/auth/register", async (c) => {
  const body = await c.req.json<{
    username?: string;
    verifier?: string;
    recoveryVerifier?: string;
    totpSecret?: string;
  }>();

  const username = (body.username || "").trim();
  const verifier = (body.verifier || "").trim();
  const recoveryVerifier = (body.recoveryVerifier || "").trim();
  const totpSecret = (body.totpSecret || "").trim();

  if (!username || !verifier) {
    return c.json({ error: "Username and password verifier are required." }, 400);
  }

  if (username.length < 3 || !/^[a-zA-Z0-9_-]+$/.test(username)) {
    return c.json(
      {
        error:
          "Username must be at least 3 characters and contain only letters, numbers, hyphens, or underscores.",
      },
      400
    );
  }

  const userKey = `user:${username.toLowerCase()}`;
  const existing = await c.env.CLOUDSYNC_KV.get(userKey);
  if (existing) {
    return c.json({ error: "Username is already taken." }, 400);
  }

  const userId = crypto.randomUUID();
  const userData = {
    id: userId,
    username,
    verifier,
    recoveryVerifier: recoveryVerifier || undefined,
    totpSecret: totpSecret || undefined,
    createdAt: Date.now(),
  };

  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(userData));

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const token = await signJwt(
    {
      sub: userId,
      username,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 90, // 90 days
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: userId, username },
  });
});

// 3. Multi-User: Log In with 2FA check
app.post("/api/auth/login", async (c) => {
  const body = await c.req.json<{
    username?: string;
    verifier?: string;
    totpCode?: string;
  }>();

  const username = (body.username || "").trim();
  const verifier = (body.verifier || "").trim();
  const totpCode = (body.totpCode || "").trim();

  if (!username || !verifier) {
    return c.json({ error: "Username and password are required." }, 400);
  }

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);
  if (!raw) {
    return c.json({ error: "Invalid username or password." }, 401);
  }

  const user = JSON.parse(raw);
  if (user.verifier !== verifier) {
    return c.json({ error: "Invalid username or password." }, 401);
  }

  // Check 2FA if enabled for this user
  if (user.totpSecret) {
    if (!totpCode) {
      return c.json({
        ok: false,
        requires2FA: true,
        message: "2FA authentication code required.",
      });
    }
    const isValid = await verifyTotpCode(user.totpSecret, totpCode);
    if (!isValid) {
      return c.json({ error: "Invalid 2FA verification code." }, 401);
    }
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const token = await signJwt(
    {
      sub: user.id,
      username: user.username,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 90,
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: user.id, username: user.username },
  });
});

// 4. Multi-User: Recover Account / Reset Password via Recovery Key
app.post("/api/auth/recover", async (c) => {
  const body = await c.req.json<{
    username?: string;
    recoveryVerifier?: string;
    newVerifier?: string;
  }>();

  const username = (body.username || "").trim();
  const recoveryVerifier = (body.recoveryVerifier || "").trim();
  const newVerifier = (body.newVerifier || "").trim();

  if (!username || !recoveryVerifier || !newVerifier) {
    return c.json(
      {
        error:
          "Username, recovery code verifier, and new password verifier are required.",
      },
      400
    );
  }

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);
  if (!raw) {
    return c.json({ error: "User not found or invalid recovery key." }, 404);
  }

  const user = JSON.parse(raw);
  if (!user.recoveryVerifier || user.recoveryVerifier !== recoveryVerifier) {
    return c.json({ error: "Invalid recovery key." }, 401);
  }

  user.verifier = newVerifier;
  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const token = await signJwt(
    {
      sub: user.id,
      username: user.username,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 90,
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: user.id, username: user.username },
    message: "Password reset successfully.",
  });
});

// =============================================================================
// AUTHENTICATION MIDDLEWARE FOR SYNC & USER API
// =============================================================================
app.use("/api/*", async (c, next) => {
  if (
    c.req.path === "/api/info" ||
    c.req.path.startsWith("/api/auth/")
  ) {
    return next();
  }

  const authHeader = c.req.header("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.*)$/i);
  if (!match) {
    return c.json({ error: "Unauthorized: Missing Bearer token." }, 401);
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const payload = await verifyJwt(match[1], secret);

  if (!payload || !payload.sub) {
    return c.json({ error: "Unauthorized: Invalid or expired token." }, 401);
  }

  c.set("userId", payload.sub);
  c.set("username", payload.username || "User");
  await next();
});

// =============================================================================
// USER PROFILE & STORAGE USAGE
// =============================================================================
app.get("/api/user/me", async (c) => {
  const userId = c.get("userId");
  const username = c.get("username");

  // Sum storage used in R2
  let storageUsedBytes = 0;
  let cursor: string | undefined = undefined;
  let truncated = true;

  while (truncated) {
    const list = await c.env.CLOUDSYNC_BUCKET.list({
      prefix: `users/${userId}/`,
      cursor,
      limit: 1000,
    });
    for (const obj of list.objects) {
      storageUsedBytes += obj.size;
    }
    truncated = list.truncated;
    cursor = list.truncated ? list.cursor : undefined;
  }

  // Check if user has 2FA enabled
  let has2FA = false;
  if (c.env.CLOUDSYNC_KV && username && username !== "Owner") {
    const raw = await c.env.CLOUDSYNC_KV.get(`user:${username.toLowerCase()}`);
    if (raw) {
      const user = JSON.parse(raw);
      has2FA = Boolean(user.totpSecret);
    }
  }

  return c.json({
    ok: true,
    userId,
    username,
    has2FA,
    storageUsedBytes,
    quotaBytes: 10 * 1024 * 1024 * 1024, // 10 GB R2 free tier
  });
});

// Set up / enable 2FA
app.post("/api/user/setup-2fa", async (c) => {
  const username = c.get("username");
  const body = await c.req.json<{ totpSecret?: string; totpCode?: string }>();
  const totpSecret = (body.totpSecret || "").trim();
  const totpCode = (body.totpCode || "").trim();

  if (!totpSecret || !totpCode) {
    return c.json(
      { error: "TOTP secret and 6-digit verification code are required." },
      400
    );
  }

  const isValid = await verifyTotpCode(totpSecret, totpCode);
  if (!isValid) {
    return c.json(
      {
        error:
          "Invalid 2FA code. Please check your authenticator app and device clock.",
      },
      400
    );
  }

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);
  if (!raw) {
    return c.json({ error: "User not found." }, 404);
  }

  const user = JSON.parse(raw);
  user.totpSecret = totpSecret;
  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));

  return c.json({
    ok: true,
    message: "Two-factor authentication enabled successfully.",
  });
});

// Disable 2FA
app.post("/api/user/disable-2fa", async (c) => {
  const username = c.get("username");
  const body = await c.req.json<{ verifier?: string }>();
  const verifier = (body.verifier || "").trim();

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);
  if (!raw) {
    return c.json({ error: "User not found." }, 404);
  }

  const user = JSON.parse(raw);
  if (user.verifier !== verifier) {
    return c.json({ error: "Invalid password." }, 401);
  }

  delete user.totpSecret;
  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));

  return c.json({ ok: true, message: "Two-factor authentication disabled." });
});

// =============================================================================
// SYNC API (FakeFs Remote Backend)
// =============================================================================

export interface VaultChange {
  rev: number;
  key: string;
  action: "put" | "delete" | "cursor";
  mtime: number;
  size?: number;
  cursor?: { line: number; ch: number };
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
  const rev = Date.now();
  const revKey = `vault_rev:${userId}:${vault}`;
  const changesKey = `vault_changes:${userId}:${vault}`;

  try {
    const existingRaw = await env.CLOUDSYNC_KV.get(changesKey);
    let changes: VaultChange[] = [];
    if (existingRaw) {
      try {
        changes = JSON.parse(existingRaw);
      } catch {}
    }
    changes.unshift({ rev, key, action, mtime, size, cursor });
    if (changes.length > 100) {
      changes = changes.slice(0, 100);
    }
    await Promise.all([
      env.CLOUDSYNC_KV.put(revKey, `${rev}`),
      env.CLOUDSYNC_KV.put(changesKey, JSON.stringify(changes)),
    ]);
  } catch (err) {
    console.error("Failed to record vault change:", err);
  }

  return rev;
}

// List all files in vault (Walk)
app.get("/api/sync/walk", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const prefix = `users/${userId}/vaults/${vault}/`;

  const files: Array<{
    key: string;
    keyRaw: string;
    size: number;
    sizeRaw: number;
    mtimeCli?: number;
    mtimeSvr?: number;
    etag?: string;
  }> = [];

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

  const revKey = `vault_rev:${userId}:${vault}`;
  const latestRevStr = await c.env.CLOUDSYNC_KV.get(revKey);
  const latestRev = latestRevStr ? Number.parseInt(latestRevStr, 10) : 0;

  return c.json({ ok: true, files, revision: latestRev });
});

// Real-Time Changes Feed (Fast invalidation / pull)
app.get("/api/sync/changes", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const sinceStr = c.req.query("since");
  const since = sinceStr ? Number.parseInt(sinceStr, 10) : 0;

  const revKey = `vault_rev:${userId}:${vault}`;
  const latestRevStr = await c.env.CLOUDSYNC_KV.get(revKey);
  const latestRev = latestRevStr ? Number.parseInt(latestRevStr, 10) : 0;

  if (since > 0 && latestRev <= since) {
    return c.json({
      ok: true,
      revision: latestRev,
      fullScanNeeded: false,
      changes: [],
    });
  }

  const changesKey = `vault_changes:${userId}:${vault}`;
  const rawChanges = await c.env.CLOUDSYNC_KV.get(changesKey);
  let allChanges: VaultChange[] = [];
  if (rawChanges) {
    try {
      allChanges = JSON.parse(rawChanges);
    } catch {}
  }

  const changes = since > 0
    ? allChanges.filter((ch) => ch.rev > since)
    : allChanges;

  const oldestInRing =
    allChanges.length > 0 ? allChanges[allChanges.length - 1].rev : 0;
  const fullScanNeeded =
    since > 0 && allChanges.length >= 100 && since < oldestInRing;

  return c.json({
    ok: true,
    revision: latestRev,
    fullScanNeeded,
    changes,
  });
});

// Get file content or metadata
app.get("/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key");

  if (!key) {
    return c.json({ error: "Missing key parameter" }, 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;
  const obj = await c.env.CLOUDSYNC_BUCKET.get(r2Key);

  if (!obj) {
    return c.text("File not found", 404);
  }

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (obj.customMetadata?.mtime) {
    headers.set("x-mtime", obj.customMetadata.mtime);
  }
  if (obj.customMetadata?.ctime) {
    headers.set("x-ctime", obj.customMetadata.ctime);
  }
  headers.set("content-length", `${obj.size}`);

  return new Response(obj.body, { headers });
});

// HEAD file metadata
app.on("HEAD", "/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key");

  if (!key) {
    return c.text("Missing key parameter", 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;
  const obj = await c.env.CLOUDSYNC_BUCKET.head(r2Key);

  if (!obj) {
    return c.text("File not found", 404);
  }

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (obj.customMetadata?.mtime) {
    headers.set("x-mtime", obj.customMetadata.mtime);
  }
  if (obj.customMetadata?.ctime) {
    headers.set("x-ctime", obj.customMetadata.ctime);
  }
  headers.set("content-length", `${obj.size}`);

  return new Response(null, { headers });
});

// Upload file
app.put("/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key");

  if (!key) {
    return c.json({ error: "Missing key parameter" }, 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;
  const mtime = c.req.header("x-mtime") || `${Date.now()}`;
  const ctime = c.req.header("x-ctime") || mtime;
  const contentType = c.req.header("content-type") || "application/octet-stream";

  const body = await c.req.raw.arrayBuffer();

  const obj = await c.env.CLOUDSYNC_BUCKET.put(r2Key, body, {
    customMetadata: { mtime, ctime },
    httpMetadata: { contentType },
  });

  const cursorLine = c.req.header("x-cursor-line");
  const cursorCh = c.req.header("x-cursor-ch");
  const cursor =
    cursorLine !== undefined && cursorCh !== undefined
      ? {
          line: Number.parseInt(cursorLine, 10),
          ch: Number.parseInt(cursorCh, 10),
        }
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

// Update cursor position only (ephemeral presence, zero R2 writes)
app.put("/api/sync/cursor", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key");
  const lineStr = c.req.header("x-cursor-line");
  const chStr = c.req.header("x-cursor-ch");

  if (!key || lineStr === undefined || chStr === undefined) {
    return c.json({ error: "Missing key or cursor coordinates" }, 400);
  }

  const cursor = {
    line: Number.parseInt(lineStr, 10),
    ch: Number.parseInt(chStr, 10),
  };

  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    key,
    "cursor",
    Date.now(),
    undefined,
    cursor
  );

  return c.json({ ok: true, revision: rev });
});

// Delete file or folder
app.delete("/api/sync/file", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key");

  if (!key) {
    return c.json({ error: "Missing key parameter" }, 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;

  if (key.endsWith("/")) {
    // Delete folder contents recursively
    let cursor: string | undefined = undefined;
    let truncated = true;
    while (truncated) {
      const list = await c.env.CLOUDSYNC_BUCKET.list({
        prefix: r2Key,
        cursor,
        limit: 500,
      });
      const toDelete = list.objects.map((o) => o.key);
      if (toDelete.length > 0) {
        await c.env.CLOUDSYNC_BUCKET.delete(toDelete);
      }
      truncated = list.truncated;
      cursor = list.truncated ? list.cursor : undefined;
    }
  }

  await c.env.CLOUDSYNC_BUCKET.delete(r2Key);
  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    key,
    "delete",
    Date.now()
  );

  return c.json({ ok: true, revision: rev });
});

// Rename file
app.post("/api/sync/rename", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const body = await c.req.json<{ from?: string; to?: string }>();

  if (!body.from || !body.to) {
    return c.json({ error: "Both 'from' and 'to' are required." }, 400);
  }

  const sourceKey = `users/${userId}/vaults/${vault}/${body.from}`;
  const targetKey = `users/${userId}/vaults/${vault}/${body.to}`;

  const sourceObj = await c.env.CLOUDSYNC_BUCKET.get(sourceKey);
  if (!sourceObj) {
    return c.json({ error: "Source file not found" }, 404);
  }

  const content = await sourceObj.arrayBuffer();
  await c.env.CLOUDSYNC_BUCKET.put(targetKey, content, {
    customMetadata: sourceObj.customMetadata,
    httpMetadata: sourceObj.httpMetadata,
  });

  await c.env.CLOUDSYNC_BUCKET.delete(sourceKey);

  await recordVaultChange(c.env, userId, vault, body.from, "delete", Date.now());
  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    body.to,
    "put",
    Number.parseInt(sourceObj.customMetadata?.mtime || `${Date.now()}`, 10),
    content.byteLength
  );

  return c.json({ ok: true, revision: rev });
});

// =============================================================================
// DEVICE IDENTITY & SETTINGS BACKUP REGISTRY
// =============================================================================

export interface DeviceInfo {
  deviceId: string;
  deviceName: string;
  platform: "desktop" | "mobile" | "unknown";
  lastActive: number;
  lastBackup?: number;
  fileCount?: number;
}

// List all registered devices for this vault
app.get("/api/sync/devices", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const devicesKey = `vault_devices:${userId}:${vault}`;

  try {
    const raw = await c.env.CLOUDSYNC_KV.get(devicesKey);
    const devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    return c.json({ devices });
  } catch (err: any) {
    return c.json({ devices: [], error: err?.message });
  }
});

// Register or update device heartbeat / backup metadata
app.put("/api/sync/devices", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const devicesKey = `vault_devices:${userId}:${vault}`;

  const body = await c.req.json().catch(() => null);
  if (!body || !body.deviceId) {
    return c.json({ error: "Missing deviceId" }, 400);
  }

  try {
    const raw = await c.env.CLOUDSYNC_KV.get(devicesKey);
    let devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    const index = devices.findIndex((d) => d.deviceId === body.deviceId);
    const now = Date.now();
    const updatedDevice: DeviceInfo = {
      deviceId: body.deviceId,
      deviceName: body.deviceName || "Unnamed Device",
      platform: body.platform || "unknown",
      lastActive: now,
      lastBackup:
        body.lastBackup !== undefined
          ? body.lastBackup
          : index >= 0
          ? devices[index].lastBackup
          : undefined,
      fileCount:
        body.fileCount !== undefined
          ? body.fileCount
          : index >= 0
          ? devices[index].fileCount
          : undefined,
    };

    if (index >= 0) {
      devices[index] = { ...devices[index], ...updatedDevice };
    } else {
      devices.push(updatedDevice);
    }

    await c.env.CLOUDSYNC_KV.put(devicesKey, JSON.stringify(devices));
    return c.json({ ok: true, device: updatedDevice });
  } catch (err: any) {
    return c.json({ error: err?.message }, 500);
  }
});

// Unregister a device
app.delete("/api/sync/devices/:deviceId", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const deviceId = c.req.param("deviceId");
  const devicesKey = `vault_devices:${userId}:${vault}`;

  try {
    const raw = await c.env.CLOUDSYNC_KV.get(devicesKey);
    let devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    devices = devices.filter((d) => d.deviceId !== deviceId);
    await c.env.CLOUDSYNC_KV.put(devicesKey, JSON.stringify(devices));
    return c.json({ ok: true });
  } catch (err: any) {
    return c.json({ error: err?.message }, 500);
  }
});

export default app;
