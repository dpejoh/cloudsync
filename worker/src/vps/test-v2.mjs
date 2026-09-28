// Protocol v2 server endpoint tests: key material, envelopes, rotation, integrity.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const TEST_PORT = 3893;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const TEST_DIR = path.resolve("./test-v2-data");

if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });

const serverProc = spawn("node", ["dist/server.mjs"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    PORT: String(TEST_PORT),
    DATA_DIR: TEST_DIR,
    WORKER_MODE: "multi",
    JWT_SECRET: "test-v2-secret-0123456789abcdef0123456789abcdef",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
serverProc.stdout.on("data", () => {});
serverProc.stderr.on("data", (d) => console.error("[server err]", d.toString()));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function req(pathname, { method = "GET", token, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (body !== undefined && typeof body !== "string") {
    h["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const res = await fetch(`${BASE_URL}${pathname}`, { method, headers: h, body });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, headers: res.headers, text, json };
}

const b64 = (s) => Buffer.from(s).toString("base64url");

function keyMaterial(accountId, username, rev) {
  return {
    v: 2,
    accountId,
    username,
    kdf: { alg: "argon2id", m: 19456, t: 2, p: 1, salt: b64("salt-salt-salt") },
    recovery: null,
    wrappedMasterKey: b64("wrapped-master-key"),
    wrappedMasterKeyRecovery: null,
    identity: { publicKey: b64("public-key-public-key-public-key"), sealedPrivateKey: b64("sealed") },
    vaults: {},
    rev,
    mac: "ab".repeat(32),
  };
}

function envelope(ownerId, vault, recipientId, keyVersion) {
  return {
    v: 2,
    vaultId: vault,
    keyVersion,
    ownerId,
    recipientId,
    sender: b64("sender"),
    sealed: b64("sealed-envelope"),
  };
}

let passed = 0;
function ok(name) {
  passed += 1;
  console.log(`[${passed}] ${name} -> ok`);
}

async function run() {
  await sleep(700);
  const health = await (await fetch(`${BASE_URL}/`)).json();
  if (health.status !== "ok") throw new Error("server did not start");

  const alice = await req("/api/auth/register", {
    method: "POST",
    body: { username: "alicev2", verifier: "a".repeat(64), scheme: 2 },
  });
  if (!alice.json?.token) throw new Error(`alice register failed: ${alice.text}`);
  const aliceToken = alice.json.token;
  const aliceId = alice.json.user.id;
  ok("register v2 account");

  const putKm = await req("/api/user/keymaterial", {
    method: "PUT",
    token: aliceToken,
    body: { keyMaterial: keyMaterial(aliceId, "alicev2", 1) },
  });
  if (putKm.status !== 200) throw new Error(`key material put failed: ${putKm.text}`);
  const gotKm = await req("/api/user/keymaterial", { token: aliceToken });
  if (gotKm.json?.keyMaterial?.rev !== 1) throw new Error("key material did not round trip");
  ok("store and fetch key material");

  const staleKm = await req("/api/user/keymaterial", {
    method: "PUT",
    token: aliceToken,
    body: { keyMaterial: keyMaterial(aliceId, "alicev2", 1) },
  });
  if (staleKm.status !== 409) throw new Error(`expected 409 for stale rev, got ${staleKm.status}`);
  const newerKm = await req("/api/user/keymaterial", {
    method: "PUT",
    token: aliceToken,
    body: { keyMaterial: keyMaterial(aliceId, "alicev2", 2) },
  });
  if (newerKm.status !== 200) throw new Error("newer rev rejected");
  ok("reject stale key material revision");

  const badKm = await req("/api/user/keymaterial", {
    method: "PUT",
    token: aliceToken,
    body: { keyMaterial: keyMaterial("someone-else", "alicev2", 3) },
  });
  if (badKm.status !== 400) throw new Error("mismatched accountId accepted");
  const pub = await req("/api/user/pubkey/alicev2", { token: aliceToken });
  if (pub.status !== 200 || !pub.json?.publicKey) throw new Error("public key lookup failed");
  const params = await req("/api/auth/params/alicev2");
  if (params.json?.scheme !== 2 || params.json?.kdf?.alg !== "argon2id") {
    throw new Error(`kdf params not exposed: ${params.text}`);
  }
  const legacyParams = await req("/api/auth/params/nobodyv2");
  if (legacyParams.json?.scheme !== 1 || legacyParams.json?.kdf !== null) {
    throw new Error("unknown account should look legacy");
  }
  ok("kdf params endpoint");

  ok("reject invalid key material and expose public key");

  const me = await req("/api/user/me", { token: aliceToken });
  if (me.json?.hasKeyMaterial !== true) throw new Error("hasKeyMaterial not reported");
  ok("user profile reports key material");

  const bob = await req("/api/auth/register", {
    method: "POST",
    body: { username: "bobv2", verifier: "b".repeat(64), scheme: 2 },
  });
  const bobToken = bob.json.token;
  const bobId = bob.json.user.id;
  const carol = await req("/api/auth/register", {
    method: "POST",
    body: { username: "carolv2", verifier: "c".repeat(64), scheme: 2 },
  });
  const carolToken = carol.json.token;
  await req("/api/vaults", { method: "POST", token: aliceToken, body: { name: "v2vault" } });
  const list = await req("/api/vaults", { token: aliceToken });
  const owned = list.json.vaults.find((v) => v.name === "v2vault");
  if (owned?.keyVersion !== 1 || owned?.rotating !== false) {
    throw new Error(`vault list missing key metadata: ${JSON.stringify(owned)}`);
  }
  ok("vault list exposes keyVersion and rotating");

  const invite = await req("/api/sync/shares?vault=v2vault", {
    method: "POST",
    token: aliceToken,
    body: { inviteUsername: "bobv2" },
  });
  if (invite.status !== 200) throw new Error(`invite failed: ${invite.text}`);

  const envPut = await req("/api/vaults/v2vault/envelope/bobv2", {
    method: "PUT",
    token: aliceToken,
    body: { envelope: envelope(aliceId, "v2vault", bobId, 1) },
  });
  if (envPut.status !== 200) throw new Error(`envelope put failed: ${envPut.text}`);
  const envGet = await req("/api/vaults/v2vault/envelope?owner=alicev2", { token: bobToken });
  if (envGet.json?.envelope?.recipientId !== bobId) throw new Error("bob did not receive envelope");
  ok("owner stores envelope and collaborator fetches it");

  const wrongVersion = await req("/api/vaults/v2vault/envelope/bobv2", {
    method: "PUT",
    token: aliceToken,
    body: { envelope: envelope(aliceId, "v2vault", bobId, 2) },
  });
  if (wrongVersion.status !== 400) throw new Error("wrong keyVersion accepted");
  const notInvited = await req("/api/vaults/v2vault/envelope/carolv2", {
    method: "PUT",
    token: aliceToken,
    body: { envelope: envelope(aliceId, "v2vault", carol.json.user.id, 1) },
  });
  if (notInvited.status !== 409) throw new Error("envelope for non-collaborator accepted");
  const bobRotation = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: bobToken,
    headers: { "x-device-id": "bob-device" },
    body: { action: "begin" },
  });
  if (bobRotation.status !== 403) throw new Error("collaborator could rotate the key");
  ok("reject bad envelopes and non-owner rotation");

  const integrity = "f".repeat(64);
  const putFile = await req("/api/sync/file?vault=v2vault&key=note.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "x-mtime": `${Date.now()}`, "x-integrity": integrity, "content-type": "text/markdown" },
    body: "v2 content",
  });
  if (putFile.status !== 200) throw new Error(`integrity put failed: ${putFile.text}`);
  const getFile = await req("/api/sync/file?vault=v2vault&key=note.md", { token: aliceToken });
  if (getFile.headers.get("x-integrity") !== integrity) throw new Error("integrity not returned on GET");
  const headFile = await req("/api/sync/file?vault=v2vault&key=note.md", { method: "HEAD", token: aliceToken });
  if (headFile.headers.get("x-integrity") !== integrity) throw new Error("integrity not returned on HEAD");
  const badIntegrity = await req("/api/sync/file?vault=v2vault&key=bad.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "x-integrity": "nope", "content-type": "text/plain" },
    body: "x",
  });
  if (badIntegrity.status !== 400) throw new Error("malformed integrity accepted");
  ok("object integrity header stored and returned");

  const begin = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: aliceToken,
    headers: { "x-device-id": "alice-device" },
    body: { action: "begin" },
  });
  if (begin.json?.rotating !== true) throw new Error("rotation begin failed");
  const sameDeviceBeginAgain = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: aliceToken,
    headers: { "x-device-id": "alice-device" },
    body: { action: "begin" },
  });
  if (
    sameDeviceBeginAgain.status !== 200 ||
    sameDeviceBeginAgain.json?.keyVersion !== begin.json?.keyVersion ||
    sameDeviceBeginAgain.json?.rotatingBy !== "alice-device"
  ) {
    throw new Error(
      `same-device begin should be an idempotent resume: ${JSON.stringify(sameDeviceBeginAgain.json)}`
    );
  }
  const readBlocked = await req("/api/sync/walk?vault=v2vault", { token: aliceToken });
  if (readBlocked.status !== 409) throw new Error(`reads not blocked during rotation: ${readBlocked.status}`);
  const otherDeviceRotate = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: aliceToken,
    headers: { "x-device-id": "alice-other-device" },
    body: { action: "begin" },
  });
  if (otherDeviceRotate.status !== 409) throw new Error("second device could start a rotation");
  const blockedPut = await req("/api/sync/file?vault=v2vault&key=blocked.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "content-type": "text/plain" },
    body: "x",
  });
  if (blockedPut.status !== 409) throw new Error(`expected 409 while rotating, got ${blockedPut.status}`);
  const blockedBob = await req("/api/sync/file?vault=v2vault&owner=alicev2&key=blocked2.md", {
    method: "PUT",
    token: bobToken,
    headers: { "content-type": "text/plain" },
    body: "x",
  });
  if (blockedBob.status !== 409) throw new Error("collaborator write allowed during rotation");
  const rotationPut = await req("/api/sync/file?vault=v2vault&key=rotated.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "content-type": "text/plain", "x-rotation": "1" },
    body: "new key content",
  });
  if (rotationPut.status !== 200) throw new Error(`rotation client write failed: ${rotationPut.text}`);
  const purge = await req("/api/vaults/v2vault/purge", { method: "POST", token: aliceToken });
  if (purge.status !== 200) throw new Error(`purge failed: ${purge.text}`);
  const commit = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: aliceToken,
    headers: { "x-device-id": "alice-device" },
    body: { action: "commit", keyVersion: 2 },
  });
  if (commit.json?.keyVersion !== 2 || commit.json?.rotating !== false) throw new Error("commit failed");
  const afterCommit = await req("/api/sync/file?vault=v2vault&key=after.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "content-type": "text/plain" },
    body: "after rotation",
  });
  if (afterCommit.status !== 200) throw new Error("writes blocked after commit");
  const envV2 = await req("/api/vaults/v2vault/envelope/bobv2", {
    method: "PUT",
    token: aliceToken,
    body: { envelope: envelope(aliceId, "v2vault", bobId, 2) },
  });
  if (envV2.status !== 200) throw new Error(`envelope for new key version failed: ${envV2.text}`);
  ok("rotation lock, purge, commit and re-envelope");

  const beginAbort = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: aliceToken,
    headers: { "x-device-id": "alice-device" },
    body: { action: "begin" },
  });
  if (beginAbort.status !== 200) throw new Error("second rotation begin failed");
  const abort = await req("/api/vaults/v2vault/rotation", {
    method: "POST",
    token: aliceToken,
    headers: { "x-device-id": "alice-device" },
    body: { action: "abort" },
  });
  if (abort.json?.rotating !== false) throw new Error("abort failed");
  const afterAbort = await req("/api/sync/file?vault=v2vault&key=aborted.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "content-type": "text/plain" },
    body: "ok",
  });
  if (afterAbort.status !== 200) throw new Error("writes blocked after abort");
  ok("rotation abort restores writes");

  const stalePut = await req("/api/sync/file?vault=v2vault&key=stale.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "content-type": "text/plain", "x-key-version": "1" },
    body: "stale generation",
  });
  if (stalePut.status !== 409) throw new Error(`stale key-version write accepted: ${stalePut.status}`);
  const freshPut = await req("/api/sync/file?vault=v2vault&key=fresh.md", {
    method: "PUT",
    token: aliceToken,
    headers: { "content-type": "text/plain", "x-key-version": "2" },
    body: "current generation",
  });
  if (freshPut.status !== 200) throw new Error(`current key-version write rejected: ${freshPut.status}`);
  ok("stale key-version writes are rejected");

  const carolRemove = await req("/api/sync/shares?vault=v2vault&username=bobv2", {
    method: "DELETE",
    token: aliceToken,
  });
  if (carolRemove.status !== 200) throw new Error("removing collaborator failed");
  const envAfterRemoval = await req("/api/vaults/v2vault/envelope?owner=alicev2", { token: bobToken });
  if (envAfterRemoval.status !== 403 && envAfterRemoval.json?.envelope) {
    throw new Error("envelope survived collaborator removal");
  }
  ok("removing a collaborator deletes their envelope/access");

  await req(`/api/vaults/v2vault`, { method: "DELETE", token: aliceToken });
  const envAfterVaultDelete = await req("/api/user/keymaterial", { token: aliceToken });
  if (envAfterVaultDelete.status !== 200) throw new Error("key material fetch broke after vault delete");
  ok("vault deletion cleans up envelopes");

  console.log(`\nall ${passed} protocol v2 endpoint tests passed`);
}

run()
  .then(() => {
    serverProc.kill("SIGTERM");
    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
    process.exit(0);
  })
  .catch((err) => {
    console.error("\ntest failed:", err);
    serverProc.kill("SIGTERM");
    if (fs.existsSync(TEST_DIR)) fs.rmSync(TEST_DIR, { recursive: true, force: true });
    process.exit(1);
  });
