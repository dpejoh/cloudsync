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

// 1. Strict OWASP Security Response Headers
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-XSS-Protection", "1; mode=block");
});

// 2. Enable CORS for Obsidian desktop, mobile, and web clients
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
      "Retry-After",
    ],
  })
);

// 3. Payload size guards for auth and user endpoints (max 16KB)
app.use("/api/auth/*", async (c, next) => {
  const cl = c.req.header("content-length");
  if (cl && Number.parseInt(cl, 10) > 16384) {
    return c.json({ error: "Payload too large." }, 413);
  }
  await next();
});

app.use("/api/user/*", async (c, next) => {
  const cl = c.req.header("content-length");
  if (cl && Number.parseInt(cl, 10) > 16384) {
    return c.json({ error: "Payload too large." }, 413);
  }
  await next();
});

// Health check and service info
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
    version: "2.1.0",
    mode,
    requiresSetup: mode === "single" && !hasPassword,
  });
});

// =============================================================================
// CRYPTOGRAPHIC & SECURITY UTILITIES
// =============================================================================

/**
 * Constant-Time String Equality Comparison
 * Prevents side-channel timing attacks by checking every byte without early exit.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  const maxLen = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;

  for (let i = 0; i < maxLen; i++) {
    const byteA = i < aBytes.length ? aBytes[i] : 0;
    const byteB = i < bBytes.length ? bBytes[i] : 0;
    diff |= byteA ^ byteB;
  }

  return diff === 0;
}

/**
 * Server-Side HMAC-SHA256 Pepper
 * Double-hashes client-derived PBKDF2 verifiers with the worker's secret key.
 * Guarantees that even if KV is leaked, offline dictionary attacks cannot crack passwords.
 */
export async function pepperVerifier(verifier: string, secret: string): Promise<string> {
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
    enc.encode(`cloudsync-pepper:${verifier.toLowerCase()}`)
  );
  const bytes = new Uint8Array(sig);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return `v2:${hex}`;
}

/**
 * Verifies a stored verifier against an incoming candidate.
 * Handles transparent zero-downtime migration from legacy unpeppered hashes to v2 peppered hashes.
 */
export async function verifyPasswordVerifier(
  stored: string,
  incoming: string,
  secret: string
): Promise<{ valid: boolean; needsUpgrade: boolean }> {
  if (stored.startsWith("v2:")) {
    const expected = await pepperVerifier(incoming, secret);
    return { valid: timingSafeEqual(stored, expected), needsUpgrade: false };
  } else {
    // Legacy verifier (raw PBKDF2 hash)
    const match = timingSafeEqual(stored.toLowerCase(), incoming.toLowerCase());
    return { valid: match, needsUpgrade: match };
  }
}

/**
 * Dummy operation to equalize execution time when an account does not exist.
 * Completely eliminates timing-based username enumeration.
 */
export async function dummyTimingEqual(incoming: string, secret: string): Promise<void> {
  await pepperVerifier(incoming, secret);
  timingSafeEqual(
    "v2:0000000000000000000000000000000000000000000000000000000000000000",
    "v2:1111111111111111111111111111111111111111111111111111111111111111"
  );
}

// =============================================================================
// EDGE RATE LIMITING (Sliding Window in KV)
// =============================================================================

function getClientIp(c: any): string {
  const cfIp = c.req.header("cf-connecting-ip");
  if (cfIp) return cfIp.trim();
  const realIp = c.req.header("x-real-ip");
  if (realIp) return realIp.trim();
  const fwd = c.req.header("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  return "127.0.0.1";
}

interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds?: number;
}

async function checkRateLimit(
  kv: KVNamespace | undefined,
  prefix: string,
  maxAttempts: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  if (!kv) return { allowed: true };
  const key = `rl:${prefix}`;
  const raw = await kv.get(key);
  if (!raw) return { allowed: true };

  try {
    const data = JSON.parse(raw);
    if (data.count >= maxAttempts) {
      const elapsed = Math.floor((Date.now() - (data.firstAt || Date.now())) / 1000);
      const retryAfter = Math.max(1, windowSeconds - elapsed);
      return { allowed: false, retryAfterSeconds: retryAfter };
    }
  } catch {}

  return { allowed: true };
}

async function recordFailedAttempt(
  kv: KVNamespace | undefined,
  prefix: string,
  windowSeconds: number
): Promise<void> {
  if (!kv) return;
  const key = `rl:${prefix}`;
  const raw = await kv.get(key);
  const now = Date.now();
  let count = 1;
  let firstAt = now;

  if (raw) {
    try {
      const data = JSON.parse(raw);
      count = (data.count || 0) + 1;
      firstAt = data.firstAt || now;
    } catch {}
  }

  await kv.put(
    key,
    JSON.stringify({ count, firstAt }),
    { expirationTtl: windowSeconds }
  );
}

async function resetRateLimit(
  kv: KVNamespace | undefined,
  prefix: string
): Promise<void> {
  if (!kv) return;
  await kv.delete(`rl:${prefix}`);
}

// =============================================================================
// INPUT VALIDATION & SANITIZATION
// =============================================================================

function isValidUsername(username: string): boolean {
  return typeof username === "string" && /^[a-zA-Z0-9_-]{3,32}$/.test(username);
}

function isValidHexHash(hash: string): boolean {
  return typeof hash === "string" && /^[a-fA-F0-9]{64}$/.test(hash);
}

function isValidTotpSecret(secret: string): boolean {
  return typeof secret === "string" && /^[A-Z2-7]{16,64}$/.test(secret);
}

function isValidTotpCode(code: string): boolean {
  return typeof code === "string" && /^\d{6}$/.test(code);
}

function isValidVaultName(vault: string): boolean {
  return typeof vault === "string" && /^[a-zA-Z0-9._-]{1,64}$/.test(vault);
}

function isValidFileKey(key: string): boolean {
  if (!key || typeof key !== "string" || key.length > 1024) return false;
  if (key.startsWith("/") || key.includes("\\")) return false;
  // Block directory traversal segments like '../', '/../', or trailing '/..'
  if (/(^|[/\\])\.\.([/\\]|$)/.test(key)) return false;
  return true;
}

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

    const header = JSON.parse(base64UrlDecode(headerB64));
    if (header.alg !== "HS256") return null;

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

/**
 * Verifies TOTP code against RFC 6238 window with replay protection.
 * If the current code matches an already-consumed time step, it is rejected.
 */
async function verifyTotpCodeWithReplayCheck(
  secretBase32: string,
  userCode: string,
  lastStep: number = 0
): Promise<{ valid: boolean; matchedStep?: number }> {
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  const cleanCode = userCode.trim();
  for (let step = currentStep - 1; step <= currentStep + 1; step++) {
    const validCode = await generateTotpCode(secretBase32, step);
    if (timingSafeEqual(validCode, cleanCode)) {
      if (step <= lastStep) {
        // Replay detected!
        return { valid: false, matchedStep: undefined };
      }
      return { valid: true, matchedStep: step };
    }
  }
  return { valid: false };
}

// =============================================================================
// AUTH ROUTES
// =============================================================================

// 1. Single-User Mode Login / Unlock
app.post("/api/auth/single-login", async (c) => {
  const clientIp = getClientIp(c);
  // IP limit for single-user mode: 10 attempts per 5 minutes
  const ipLimit = await checkRateLimit(c.env.CLOUDSYNC_KV, `ip:single:${clientIp}`, 10, 300);
  if (!ipLimit.allowed) {
    return c.json(
      {
        error: `Too many failed attempts. Please wait ${ipLimit.retryAfterSeconds} seconds before trying again.`,
        retryAfter: ipLimit.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${ipLimit.retryAfterSeconds}` }
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
    return c.json({ error: "A valid 64-character password verifier is required." }, 400);
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";

  if (c.env.CLOUDSYNC_KV) {
    let stored = await c.env.CLOUDSYNC_KV.get("single:verifier");
    if (!stored) {
      // First setup: initialize single-user password verifier with pepper
      const peppered = await pepperVerifier(verifier, secret);
      await c.env.CLOUDSYNC_KV.put("single:verifier", peppered);
      stored = peppered;
    }

    const check = await verifyPasswordVerifier(stored, verifier, secret);
    if (!check.valid) {
      await dummyTimingEqual(verifier, secret);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:single:${clientIp}`, 300);
      return c.json({ error: "Invalid master password." }, 401);
    }

    if (check.needsUpgrade) {
      const peppered = await pepperVerifier(verifier, secret);
      await c.env.CLOUDSYNC_KV.put("single:verifier", peppered);
    }
  }

  await resetRateLimit(c.env.CLOUDSYNC_KV, `ip:single:${clientIp}`);

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
  const clientIp = getClientIp(c);
  // Rate limit registration by IP: max 10 registrations per 10 minutes
  const regLimit = await checkRateLimit(c.env.CLOUDSYNC_KV, `ip:reg:${clientIp}`, 10, 600);
  if (!regLimit.allowed) {
    return c.json(
      {
        error: `Too many registration attempts. Please wait ${regLimit.retryAfterSeconds} seconds before trying again.`,
        retryAfter: regLimit.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${regLimit.retryAfterSeconds}` }
    );
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

  if (!isValidUsername(username)) {
    return c.json(
      {
        error:
          "Username must be between 3 and 32 characters and contain only letters, numbers, hyphens, or underscores.",
      },
      400
    );
  }

  if (!isValidHexHash(verifier)) {
    return c.json(
      { error: "Password verifier must be a valid 64-character hex hash." },
      400
    );
  }

  if (recoveryVerifier && !isValidHexHash(recoveryVerifier)) {
    return c.json(
      { error: "Recovery verifier must be a valid 64-character hex hash." },
      400
    );
  }

  if (totpSecret && !isValidTotpSecret(totpSecret)) {
    return c.json(
      { error: "TOTP secret must be a valid Base32 string (16-64 characters)." },
      400
    );
  }

  const userKey = `user:${username.toLowerCase()}`;
  const existing = await c.env.CLOUDSYNC_KV.get(userKey);
  if (existing) {
    return c.json({ error: "Username is already taken." }, 400);
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";

  // Pepper the verifier and recovery verifier with server secret before persisting
  const pepperedVerifier = await pepperVerifier(verifier, secret);
  const pepperedRecovery = recoveryVerifier
    ? await pepperVerifier(recoveryVerifier, secret)
    : undefined;

  const userId = crypto.randomUUID();
  const userData = {
    id: userId,
    username,
    verifier: pepperedVerifier,
    recoveryVerifier: pepperedRecovery,
    totpSecret: totpSecret || undefined,
    createdAt: Date.now(),
  };

  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(userData));
  await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:reg:${clientIp}`, 600);

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
  const clientIp = getClientIp(c);
  // IP limit: 20 failed attempts per 5 minutes to prevent IP-wide lockout while stopping bots
  const ipLimit = await checkRateLimit(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`, 20, 300);
  if (!ipLimit.allowed) {
    return c.json(
      {
        error: `Too many failed login attempts from this network. Please wait ${ipLimit.retryAfterSeconds} seconds before trying again.`,
        retryAfter: ipLimit.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${ipLimit.retryAfterSeconds}` }
    );
  }

  let body: {
    username?: string;
    verifier?: string;
    totpCode?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const username = (body?.username || "").trim();
  const verifier = (body?.verifier || "").trim();
  const totpCode = (body?.totpCode || "").trim();

  if (!username || !verifier) {
    return c.json({ error: "Username and password are required." }, 400);
  }

  if (!isValidUsername(username) || !isValidHexHash(verifier)) {
    return c.json({ error: "Invalid username or password." }, 401);
  }

  // Account limit: 5 failed attempts per 5 minutes to prevent targeted brute force
  const userLimit = await checkRateLimit(
    c.env.CLOUDSYNC_KV,
    `user:login:${username.toLowerCase()}`,
    5,
    300
  );
  if (!userLimit.allowed) {
    return c.json(
      {
        error: `Too many failed attempts on this account. Please wait ${userLimit.retryAfterSeconds} seconds before trying again.`,
        retryAfter: userLimit.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${userLimit.retryAfterSeconds}` }
    );
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);

  if (!raw) {
    // Constant-time dummy hash to prevent user enumeration via timing
    await dummyTimingEqual(verifier, secret);
    await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`, 300);
    await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:login:${username.toLowerCase()}`, 300);
    return c.json({ error: "Invalid username or password." }, 401);
  }

  let user: any;
  try {
    user = JSON.parse(raw);
  } catch {
    return c.json({ error: "Account corrupted. Contact administrator." }, 500);
  }

  const authCheck = await verifyPasswordVerifier(user.verifier, verifier, secret);
  if (!authCheck.valid) {
    await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`, 300);
    await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:login:${username.toLowerCase()}`, 300);
    return c.json({ error: "Invalid username or password." }, 401);
  }

  // Auto-upgrade legacy stored verifiers to peppered v2
  if (authCheck.needsUpgrade) {
    user.verifier = await pepperVerifier(verifier, secret);
    await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));
  }

  // 2FA check if enabled
  if (user.totpSecret) {
    if (!totpCode) {
      return c.json({
        ok: false,
        requires2FA: true,
        message: "2FA authentication code required.",
      });
    }

    if (!isValidTotpCode(totpCode)) {
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`, 300);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:login:${username.toLowerCase()}`, 300);
      return c.json({ error: "2FA code must be exactly 6 digits." }, 400);
    }

    const totpResult = await verifyTotpCodeWithReplayCheck(
      user.totpSecret,
      totpCode,
      user.lastTotpStep || 0
    );

    if (!totpResult.valid) {
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`, 300);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:login:${username.toLowerCase()}`, 300);
      return c.json({ error: "Invalid or already used 2FA verification code." }, 401);
    }

    user.lastTotpStep = totpResult.matchedStep;
    await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));
  }

  // Reset rate limit counters on successful authentication
  await Promise.all([
    resetRateLimit(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`),
    resetRateLimit(c.env.CLOUDSYNC_KV, `user:login:${username.toLowerCase()}`),
  ]);

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

// 4. Multi-User: Recover Account / Reset Password via 2FA Code or Recovery Key
app.post("/api/auth/recover", async (c) => {
  const clientIp = getClientIp(c);
  // IP limit: 20 failed recovery attempts per 5 minutes
  const ipLimit = await checkRateLimit(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`, 20, 300);
  if (!ipLimit.allowed) {
    return c.json(
      {
        error: `Too many failed recovery attempts from this network. Please wait ${ipLimit.retryAfterSeconds} seconds before trying again.`,
        retryAfter: ipLimit.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${ipLimit.retryAfterSeconds}` }
    );
  }

  let body: {
    username?: string;
    totpCode?: string;
    recoveryVerifier?: string;
    newVerifier?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const username = (body?.username || "").trim();
  const totpCode = (body?.totpCode || "").trim();
  const recoveryVerifier = (body?.recoveryVerifier || "").trim();
  const newVerifier = (body?.newVerifier || "").trim();

  if (!username || !newVerifier) {
    return c.json(
      {
        error: "Username and new password verifier are required.",
      },
      400
    );
  }

  if (!totpCode && !recoveryVerifier) {
    return c.json(
      {
        error: "2FA verification code or recovery key is required.",
      },
      400
    );
  }

  if (!isValidUsername(username) || !isValidHexHash(newVerifier)) {
    return c.json({ error: "Invalid recovery credentials." }, 401);
  }

  if (totpCode && !isValidTotpCode(totpCode)) {
    return c.json({ error: "2FA code must be exactly 6 digits." }, 400);
  }

  if (recoveryVerifier && !isValidHexHash(recoveryVerifier)) {
    return c.json({ error: "Recovery verifier must be a valid 64-character hex hash." }, 400);
  }

  const userLimit = await checkRateLimit(
    c.env.CLOUDSYNC_KV,
    `user:recover:${username.toLowerCase()}`,
    5,
    300
  );
  if (!userLimit.allowed) {
    return c.json(
      {
        error: `Too many failed recovery attempts on this account. Please wait ${userLimit.retryAfterSeconds} seconds before trying again.`,
        retryAfter: userLimit.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${userLimit.retryAfterSeconds}` }
    );
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);

  if (!raw) {
    await dummyTimingEqual(newVerifier, secret);
    await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`, 300);
    await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:recover:${username.toLowerCase()}`, 300);
    return c.json({ error: "Invalid username or verification code." }, 401);
  }

  let user: any;
  try {
    user = JSON.parse(raw);
  } catch {
    return c.json({ error: "Account corrupted. Contact administrator." }, 500);
  }

  if (totpCode) {
    // 2FA TOTP verification
    if (!user.totpSecret) {
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`, 300);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:recover:${username.toLowerCase()}`, 300);
      return c.json(
        {
          error:
            "2FA was not set up for this account. Password cannot be reset without 2FA.",
        },
        400
      );
    }

    const totpResult = await verifyTotpCodeWithReplayCheck(
      user.totpSecret,
      totpCode,
      user.lastTotpStep || 0
    );

    if (!totpResult.valid) {
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`, 300);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:recover:${username.toLowerCase()}`, 300);
      return c.json({ error: "Invalid or expired 2FA verification code." }, 401);
    }

    user.lastTotpStep = totpResult.matchedStep;
  } else if (recoveryVerifier) {
    // Legacy recovery key verification
    if (!user.recoveryVerifier) {
      await dummyTimingEqual(recoveryVerifier, secret);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`, 300);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:recover:${username.toLowerCase()}`, 300);
      return c.json({ error: "No recovery key set for this account." }, 401);
    }

    const recCheck = await verifyPasswordVerifier(user.recoveryVerifier, recoveryVerifier, secret);
    if (!recCheck.valid) {
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`, 300);
      await recordFailedAttempt(c.env.CLOUDSYNC_KV, `user:recover:${username.toLowerCase()}`, 300);
      return c.json({ error: "Invalid recovery key." }, 401);
    }

    if (recCheck.needsUpgrade) {
      user.recoveryVerifier = await pepperVerifier(recoveryVerifier, secret);
    }
  }

  // Update password verifier with peppered version
  user.verifier = await pepperVerifier(newVerifier, secret);
  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));

  await Promise.all([
    resetRateLimit(c.env.CLOUDSYNC_KV, `ip:recover:${clientIp}`),
    resetRateLimit(c.env.CLOUDSYNC_KV, `user:recover:${username.toLowerCase()}`),
    resetRateLimit(c.env.CLOUDSYNC_KV, `ip:login:${clientIp}`),
    resetRateLimit(c.env.CLOUDSYNC_KV, `user:login:${username.toLowerCase()}`),
  ]);

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
    has2FA: Boolean(user.totpSecret),
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

  if (!payload || !payload.sub || typeof payload.sub !== "string") {
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
      try {
        const user = JSON.parse(raw);
        has2FA = Boolean(user.totpSecret);
      } catch {}
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

  const rateCheck = await checkRateLimit(
    c.env.CLOUDSYNC_KV,
    `user:2fa:${username.toLowerCase()}`,
    5,
    300
  );
  if (!rateCheck.allowed) {
    return c.json(
      {
        error: `Too many 2FA setup attempts. Please wait ${rateCheck.retryAfterSeconds} seconds before trying again.`,
        retryAfter: rateCheck.retryAfterSeconds,
      },
      429,
      { "Retry-After": `${rateCheck.retryAfterSeconds}` }
    );
  }

  let body: { totpSecret?: string; totpCode?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const totpSecret = (body?.totpSecret || "").trim();
  const totpCode = (body?.totpCode || "").trim();

  if (!totpSecret || !totpCode) {
    return c.json(
      { error: "TOTP secret and 6-digit verification code are required." },
      400
    );
  }

  if (!isValidTotpSecret(totpSecret) || !isValidTotpCode(totpCode)) {
    return c.json(
      { error: "Invalid 2FA secret format or 6-digit code." },
      400
    );
  }

  const totpResult = await verifyTotpCodeWithReplayCheck(totpSecret, totpCode, 0);
  if (!totpResult.valid) {
    await recordFailedAttempt(
      c.env.CLOUDSYNC_KV,
      `user:2fa:${username.toLowerCase()}`,
      300
    );
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
  user.lastTotpStep = totpResult.matchedStep;
  await c.env.CLOUDSYNC_KV.put(userKey, JSON.stringify(user));

  await resetRateLimit(c.env.CLOUDSYNC_KV, `user:2fa:${username.toLowerCase()}`);

  return c.json({
    ok: true,
    message: "Two-factor authentication enabled successfully.",
  });
});

// Disable 2FA
app.post("/api/user/disable-2fa", async (c) => {
  const username = c.get("username");
  let body: { verifier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const verifier = (body?.verifier || "").trim();
  if (!verifier || !isValidHexHash(verifier)) {
    return c.json({ error: "Valid password verifier required." }, 400);
  }

  const userKey = `user:${username.toLowerCase()}`;
  const raw = await c.env.CLOUDSYNC_KV.get(userKey);
  if (!raw) {
    return c.json({ error: "User not found." }, 404);
  }

  const secret = c.env.JWT_SECRET || "cloudsync-secret-change-me";
  const user = JSON.parse(raw);
  const authCheck = await verifyPasswordVerifier(user.verifier, verifier, secret);
  if (!authCheck.valid) {
    return c.json({ error: "Invalid password." }, 401);
  }

  delete user.totpSecret;
  delete user.lastTotpStep;
  if (authCheck.needsUpgrade) {
    user.verifier = await pepperVerifier(verifier, secret);
  }
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

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

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

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

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
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  if (!isValidFileKey(key)) {
    return c.json({ error: "Invalid or unsafe file key parameter." }, 400);
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
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault)) {
    return c.text("Invalid vault identifier", 400);
  }

  if (!isValidFileKey(key)) {
    return c.text("Invalid or unsafe file key parameter", 400);
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
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  if (!isValidFileKey(key)) {
    return c.json({ error: "Invalid or unsafe file key parameter." }, 400);
  }

  const r2Key = `users/${userId}/vaults/${vault}/${key}`;
  const mtime = c.req.header("x-mtime") || `${Date.now()}`;
  const ctime = c.req.header("x-ctime") || mtime;
  const contentType =
    c.req.header("content-type") || "application/octet-stream";
  const body = await c.req.raw.arrayBuffer();

  // Snapshot previous version to history if it exists
  try {
    const existing = await c.env.CLOUDSYNC_BUCKET.get(r2Key);
    if (existing && existing.size > 0) {
      const existingData = await existing.arrayBuffer();
      const existingMtime = existing.customMetadata?.mtime || `${Date.now()}`;
      const histKey = `users/${userId}/history/${vault}/${key}/${existingMtime}`;
      await c.env.CLOUDSYNC_BUCKET.put(histKey, existingData, {
        customMetadata: { mtime: existingMtime, size: `${existing.size}` },
      });
    }
  } catch (e) {
    console.debug("Failed to snapshot file history:", e);
  }

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
  const key = c.req.query("key") || "";
  const lineStr = c.req.header("x-cursor-line");
  const chStr = c.req.header("x-cursor-ch");

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  if (!isValidFileKey(key) || lineStr === undefined || chStr === undefined) {
    return c.json({ error: "Missing key or invalid cursor coordinates" }, 400);
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
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  if (!isValidFileKey(key)) {
    return c.json({ error: "Invalid or unsafe file key parameter." }, 400);
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

  // Preserve in Cloud Trash before deletion (unless folder)
  if (!key.endsWith("/")) {
    try {
      const existingObj = await c.env.CLOUDSYNC_BUCKET.get(r2Key);
      if (existingObj) {
        const data = await existingObj.arrayBuffer();
        const trashKey = `users/${userId}/trash/${vault}/${key}`;
        await c.env.CLOUDSYNC_BUCKET.put(trashKey, data, {
          customMetadata: {
            ...existingObj.customMetadata,
            deletedAt: `${Date.now()}`,
          },
        });
      }
    } catch (err) {
      console.error("Failed to copy to trash:", err);
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

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  let body: { from?: string; to?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  if (!body.from || !body.to || !isValidFileKey(body.from) || !isValidFileKey(body.to)) {
    return c.json({ error: "Both 'from' and 'to' must be valid, safe file keys." }, 400);
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
// CLOUD TRASH / DELETED FILES RECOVERY
// =============================================================================

// List deleted files
app.get("/api/sync/trash", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

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

// Restore deleted file
app.post("/api/sync/trash/restore", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  let body: { key?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const key = (body?.key || "").trim();
  if (!isValidFileKey(key)) {
    return c.json({ error: "Invalid file key parameter." }, 400);
  }

  const trashKey = `users/${userId}/trash/${vault}/${key}`;
  const targetKey = `users/${userId}/vaults/${vault}/${key}`;

  const trashObj = await c.env.CLOUDSYNC_BUCKET.get(trashKey);
  if (!trashObj) {
    return c.json({ error: "Deleted file not found in trash." }, 404);
  }

  const data = await trashObj.arrayBuffer();
  const mtime = Date.now();
  await c.env.CLOUDSYNC_BUCKET.put(targetKey, data, {
    customMetadata: { mtime: `${mtime}` },
  });

  await c.env.CLOUDSYNC_BUCKET.delete(trashKey);

  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    key,
    "put",
    mtime,
    data.byteLength
  );

  return c.json({ ok: true, key, revision: rev });
});

// =============================================================================
// FILE VERSION HISTORY (Per-note cloud revisions)
// =============================================================================

// List historical versions for a file
app.get("/api/sync/history", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const key = c.req.query("key") || "";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }
  if (!isValidFileKey(key)) {
    return c.json({ error: "Invalid file key parameter." }, 400);
  }

  const prefix = `users/${userId}/history/${vault}/${key}/`;
  const list = await c.env.CLOUDSYNC_BUCKET.list({ prefix, limit: 100 });

  const versions = list.objects.map((o) => {
    const versionId = o.key.slice(prefix.length);
    const ts = Number.parseInt(versionId, 10) || o.uploaded.getTime();
    return {
      versionId,
      timestamp: ts,
      size: o.size,
    };
  });

  // Sort newest first
  versions.sort((a, b) => b.timestamp - a.timestamp);
  return c.json({ ok: true, key, versions });
});

// Get content of a specific historical version
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
  if (!obj) {
    return c.json({ error: "Historical version not found." }, 404);
  }

  c.header(
    "Content-Type",
    obj.httpMetadata?.contentType || "application/octet-stream"
  );
  c.header("Content-Length", `${obj.size}`);
  return c.body(obj.body);
});

// Restore a historical version as active note
app.post("/api/sync/history/restore", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";

  let body: { key?: string; versionId?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const key = (body?.key || "").trim();
  const versionId = (body?.versionId || "").trim();

  if (!isValidVaultName(vault) || !isValidFileKey(key) || !versionId) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const histKey = `users/${userId}/history/${vault}/${key}/${versionId}`;
  const targetKey = `users/${userId}/vaults/${vault}/${key}`;

  const histObj = await c.env.CLOUDSYNC_BUCKET.get(histKey);
  if (!histObj) {
    return c.json({ error: "Version not found." }, 404);
  }

  const data = await histObj.arrayBuffer();
  const mtime = Date.now();

  await c.env.CLOUDSYNC_BUCKET.put(targetKey, data, {
    customMetadata: { mtime: `${mtime}` },
  });

  const rev = await recordVaultChange(
    c.env,
    userId,
    vault,
    key,
    "put",
    mtime,
    data.byteLength
  );

  return c.json({ ok: true, key, revision: rev });
});

// =============================================================================
// VAULT SHARING / COLLABORATION
// =============================================================================

// List collaborators
app.get("/api/sync/shares", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  const sharesKey = `vault_shares:${userId}:${vault}`;
  const raw = await c.env.CLOUDSYNC_KV.get(sharesKey);
  const shares: string[] = raw ? JSON.parse(raw) : [];

  return c.json({ ok: true, vault, shares });
});

// Invite collaborator
app.post("/api/sync/shares", async (c) => {
  const userId = c.get("userId");
  const currentUsername = c.get("username");
  const vault = c.req.query("vault") || "default";

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  let body: { inviteUsername?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  const inviteUsername = (body?.inviteUsername || "").trim();
  if (!inviteUsername || !isValidUsername(inviteUsername)) {
    return c.json({ error: "Valid username is required." }, 400);
  }

  if (inviteUsername.toLowerCase() === currentUsername.toLowerCase()) {
    return c.json({ error: "You cannot invite yourself." }, 400);
  }

  const inviteUserKey = `user:${inviteUsername.toLowerCase()}`;
  const inviteUserRaw = await c.env.CLOUDSYNC_KV.get(inviteUserKey);
  if (!inviteUserRaw) {
    return c.json({ error: `User "${inviteUsername}" does not exist.` }, 404);
  }

  const sharesKey = `vault_shares:${userId}:${vault}`;
  const raw = await c.env.CLOUDSYNC_KV.get(sharesKey);
  let shares: string[] = raw ? JSON.parse(raw) : [];

  if (!shares.some((u) => u.toLowerCase() === inviteUsername.toLowerCase())) {
    shares.push(inviteUsername);
    await c.env.CLOUDSYNC_KV.put(sharesKey, JSON.stringify(shares));
  }

  return c.json({ ok: true, message: `Vault shared with ${inviteUsername}`, shares });
});

// Remove collaborator
app.delete("/api/sync/shares", async (c) => {
  const userId = c.get("userId");
  const vault = c.req.query("vault") || "default";
  const username = c.req.query("username");

  if (!isValidVaultName(vault) || !username) {
    return c.json({ error: "Invalid parameters." }, 400);
  }

  const sharesKey = `vault_shares:${userId}:${vault}`;
  const raw = await c.env.CLOUDSYNC_KV.get(sharesKey);
  let shares: string[] = raw ? JSON.parse(raw) : [];
  shares = shares.filter((u) => u.toLowerCase() !== username.toLowerCase());
  await c.env.CLOUDSYNC_KV.put(sharesKey, JSON.stringify(shares));

  return c.json({ ok: true, shares });
});

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

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

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

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  const devicesKey = `vault_devices:${userId}:${vault}`;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON payload." }, 400);
  }

  if (!body || !body.deviceId || typeof body.deviceId !== "string" || !/^[a-zA-Z0-9._-]{1,64}$/.test(body.deviceId)) {
    return c.json({ error: "Invalid deviceId" }, 400);
  }

  try {
    const raw = await c.env.CLOUDSYNC_KV.get(devicesKey);
    let devices: DeviceInfo[] = raw ? JSON.parse(raw) : [];
    const index = devices.findIndex((d) => d.deviceId === body.deviceId);
    const now = Date.now();
    const updatedDevice: DeviceInfo = {
      deviceId: body.deviceId,
      deviceName: String(body.deviceName || "Unnamed Device").slice(0, 64),
      platform: body.platform === "desktop" || body.platform === "mobile" ? body.platform : "unknown",
      lastActive: now,
      lastBackup:
        body.lastBackup !== undefined && typeof body.lastBackup === "number"
          ? body.lastBackup
          : index >= 0
          ? devices[index].lastBackup
          : undefined,
      fileCount:
        body.fileCount !== undefined && typeof body.fileCount === "number"
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

  if (!isValidVaultName(vault)) {
    return c.json({ error: "Invalid vault identifier." }, 400);
  }

  if (!deviceId || !/^[a-zA-Z0-9._-]{1,64}$/.test(deviceId)) {
    return c.json({ error: "Invalid deviceId" }, 400);
  }

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
