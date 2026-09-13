import { Hono } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  CLOUDSYNC_BUCKET: R2Bucket;
  CLOUDSYNC_KV: KVNamespace;
  JWT_SECRET?: string;
};

type Variables = {
  userId: string;
  email: string;
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Enable CORS for Obsidian desktop and web clients
app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type", "x-mtime", "x-ctime", "x-vault-id"],
    exposeHeaders: ["Content-Length", "x-mtime", "x-ctime", "ETag"],
  })
);

// Health check
app.get("/", (c) => {
  return c.json({
    status: "ok",
    service: "CloudSync Edge Worker",
    version: "1.0.0",
  });
});

// =============================================================================
// JWT Web Crypto Helpers (HS256)
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

// =============================================================================
// AUTH ROUTES
// =============================================================================

// Register a new user
app.post("/api/auth/register", async (c) => {
  const body = await c.req.json<{ email?: string; verifier?: string }>();
  const email = (body.email || "").trim().toLowerCase();
  const verifier = (body.verifier || "").trim();

  if (!email || !verifier) {
    return c.json({ error: "Email and verifier are required." }, 400);
  }

  // Check if user already exists
  const existing = await c.env.CLOUDSYNC_KV.get(`user:${email}`);
  if (existing) {
    return c.json({ error: "User already exists with this email." }, 400);
  }

  const userId = crypto.randomUUID();
  const userData = {
    id: userId,
    email,
    verifier,
    createdAt: Date.now(),
  };

  await c.env.CLOUDSYNC_KV.put(`user:${email}`, JSON.stringify(userData));

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const token = await signJwt(
    {
      sub: userId,
      email,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 90, // 90 days
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: userId, email },
  });
});

// Log In
app.post("/api/auth/login", async (c) => {
  const body = await c.req.json<{ email?: string; verifier?: string }>();
  const email = (body.email || "").trim().toLowerCase();
  const verifier = (body.verifier || "").trim();

  if (!email || !verifier) {
    return c.json({ error: "Email and verifier are required." }, 400);
  }

  const raw = await c.env.CLOUDSYNC_KV.get(`user:${email}`);
  if (!raw) {
    return c.json({ error: "Invalid email or password." }, 401);
  }

  const user = JSON.parse(raw);
  if (user.verifier !== verifier) {
    return c.json({ error: "Invalid email or password." }, 401);
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const token = await signJwt(
    {
      sub: user.id,
      email: user.email,
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 90,
    },
    secret
  );

  return c.json({
    ok: true,
    token,
    user: { id: user.id, email: user.email },
  });
});

// =============================================================================
// AUTHENTICATION MIDDLEWARE FOR SYNC & USER API
// =============================================================================
app.use("/api/*", async (c, next) => {
  if (c.req.path.startsWith("/api/auth/")) {
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
  c.set("email", payload.email);
  await next();
});

// =============================================================================
// USER PROFILE & STORAGE USAGE
// =============================================================================
app.get("/api/user/me", async (c) => {
  const userId = c.get("userId");
  const email = c.get("email");

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

  return c.json({
    ok: true,
    userId,
    email,
    storageUsedBytes,
    quotaBytes: 10 * 1024 * 1024 * 1024, // 10 GB R2 free tier
  });
});

// =============================================================================
// SYNC API (FakeFs Remote Backend)
// =============================================================================

export interface VaultChange {
  rev: number;
  key: string;
  action: "put" | "delete";
  mtime: number;
  size?: number;
}

async function recordVaultChange(
  env: Bindings,
  userId: string,
  vault: string,
  key: string,
  action: "put" | "delete",
  mtime: number,
  size?: number
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
    changes.unshift({ rev, key, action, mtime, size });
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
      include: ["customMetadata", "httpMetadata"],
    });

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

  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    key,
    "put",
    Number.parseInt(mtime, 10),
    body.byteLength
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

export default app;
