// Test suite for CloudSync VPS Standalone Server
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const TEST_PORT = 3891;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const TEST_DIR = path.resolve("./test-vps-data");

// Clean up previous test run
if (fs.existsSync(TEST_DIR)) {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
}

console.log("[start] launching vps standalone server on port", TEST_PORT);

const serverProc = spawn("node", ["dist/server.mjs"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    PORT: String(TEST_PORT),
    DATA_DIR: TEST_DIR,
    WORKER_MODE: "multi",
  },
  stdio: ["ignore", "pipe", "pipe"],
});

serverProc.stdout.on("data", (d) => {
  // console.log("[server]", d.toString());
});
serverProc.stderr.on("data", (d) => {
  console.error("[server err]", d.toString());
});

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runTests() {
  await sleep(600); // Give server time to bind

  const healthRes = await fetch(`${BASE_URL}/`);
  const healthJson = await healthRes.json();
  if (healthJson.status !== "ok" || healthJson.version !== "2.1.0") {
    throw new Error(`Health check failed: ${JSON.stringify(healthJson)}`);
  }
  console.log("[1/18] GET / -> ok");

  const infoRes = await fetch(`${BASE_URL}/api/info`);
  const infoJson = await infoRes.json();
  if (!infoJson.service || infoJson.mode !== "multi") {
    throw new Error(`Info check failed: ${JSON.stringify(infoJson)}`);
  }
  console.log("[2/18] GET /api/info -> ok");

  const testVerifier = "a".repeat(64);
  const regRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "alice",
      verifier: testVerifier,
    }),
  });
  const regJson = await regRes.json();
  if (!regJson.ok || !regJson.token) {
    throw new Error(`Register failed: ${JSON.stringify(regJson)}`);
  }
  const token = regJson.token;
  console.log("[3/18] POST /api/auth/register -> ok (user: alice)");

  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "alice",
      verifier: testVerifier,
    }),
  });
  const loginJson = await loginRes.json();
  if (!loginJson.ok || !loginJson.token) {
    throw new Error(`Login failed: ${JSON.stringify(loginJson)}`);
  }
  console.log("[4/18] POST /api/auth/login -> ok");

  const authHeaders = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  const createVaultRes = await fetch(`${BASE_URL}/api/vaults`, {
    method: "POST",
    headers: authHeaders,
    body: JSON.stringify({ name: "my-personal-vault" }),
  });
  const createVaultJson = await createVaultRes.json();
  if (!createVaultJson.ok || createVaultJson.name !== "my-personal-vault") {
    throw new Error(`Create vault failed: ${JSON.stringify(createVaultJson)}`);
  }
  console.log("[5/18] POST /api/vaults -> ok (vault: my-personal-vault)");

  const listVaultsRes = await fetch(`${BASE_URL}/api/vaults`, {
    headers: authHeaders,
  });
  const listVaultsJson = await listVaultsRes.json();
  if (!listVaultsJson.vaults.some((v) => v.name === "my-personal-vault")) {
    throw new Error(`List vaults failed: ${JSON.stringify(listVaultsJson)}`);
  }
  console.log("[6/18] GET /api/vaults -> ok");

  const fileContent = "Hello from CloudSync Private VPS!\nObsidian notes are awesome.";
  const putFileRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "text/markdown",
        "x-mtime": `${Date.now()}`,
        "x-ctime": `${Date.now()}`,
      },
      body: fileContent,
    }
  );
  const putFileJson = await putFileRes.json();
  if (!putFileJson.ok || putFileJson.size !== fileContent.length) {
    throw new Error(`File upload failed: ${JSON.stringify(putFileJson)}`);
  }
  console.log("[7/18] PUT /api/sync/file -> ok");

  const getFileRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const downloadedText = await getFileRes.text();
  if (downloadedText !== fileContent) {
    throw new Error(`File download content mismatch! Expected '${fileContent}', got '${downloadedText}'`);
  }
  console.log("[8/18] GET /api/sync/file -> ok");

  const headFileRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      method: "HEAD",
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  if (headFileRes.status !== 200 || !headFileRes.headers.get("etag")) {
    throw new Error(`HEAD file failed: status ${headFileRes.status}`);
  }
  console.log("[9/18] HEAD /api/sync/file -> ok");

  const walkRes = await fetch(
    `${BASE_URL}/api/sync/walk?vault=my-personal-vault`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const walkJson = await walkRes.json();
  if (!walkJson.ok || walkJson.files.length !== 1 || walkJson.files[0].key !== "Notes/Hello.md") {
    throw new Error(`Walk failed: ${JSON.stringify(walkJson)}`);
  }
  console.log("[10/18] GET /api/sync/walk -> ok");

  const cursorRes = await fetch(
    `${BASE_URL}/api/sync/cursor?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "x-cursor-line": "5",
        "x-cursor-ch": "12",
      },
    }
  );
  const cursorJson = await cursorRes.json();
  if (!cursorJson.ok || !cursorJson.revision) {
    throw new Error(`Cursor update failed: ${JSON.stringify(cursorJson)}`);
  }
  console.log("[11/18] PUT /api/sync/cursor -> ok");

  const changesRes = await fetch(
    `${BASE_URL}/api/sync/changes?vault=my-personal-vault&since=0`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const changesJson = await changesRes.json();
  if (!changesJson.ok || changesJson.changes.length < 2) {
    throw new Error(`Changes feed failed: ${JSON.stringify(changesJson)}`);
  }
  console.log("[12/18] GET /api/sync/changes -> ok");

  const newContent = "Version 2 of the document!";
  await fetch(
    `${BASE_URL}/api/sync/file?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "text/markdown",
        "x-mtime": `${Date.now()}`,
      },
      body: newContent,
    }
  );

  const histRes = await fetch(
    `${BASE_URL}/api/sync/history?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const histJson = await histRes.json();
  if (!histJson.ok || histJson.versions.length !== 1) {
    throw new Error(`History check failed: ${JSON.stringify(histJson)}`);
  }
  console.log("[13/18] GET /api/sync/history -> ok");

  await fetch(
    `${BASE_URL}/api/sync/file?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    }
  );

  const trashRes = await fetch(
    `${BASE_URL}/api/sync/trash?vault=my-personal-vault`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const trashJson = await trashRes.json();
  if (!trashJson.ok || trashJson.files.length !== 1 || trashJson.files[0].key !== "Notes/Hello.md") {
    throw new Error(`Trash check failed: ${JSON.stringify(trashJson)}`);
  }
  console.log("[14/18] DELETE /api/sync/file -> ok");

  const restoreRes = await fetch(
    `${BASE_URL}/api/sync/trash/restore?vault=my-personal-vault`,
    {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ key: "Notes/Hello.md" }),
    }
  );
  const restoreJson = await restoreRes.json();
  if (!restoreJson.ok) {
    throw new Error(`Restore failed: ${JSON.stringify(restoreJson)}`);
  }

  const restoredFileRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=my-personal-vault&key=Notes/Hello.md`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  if (restoredFileRes.status !== 200) {
    throw new Error(`Restored file not found! status: ${restoredFileRes.status}`);
  }
  console.log("[15/18] POST /api/sync/trash/restore -> ok");

  const userMeRes = await fetch(`${BASE_URL}/api/user/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const userMeJson = await userMeRes.json();
  if (!userMeJson.ok || userMeJson.storageUsedBytes <= 0) {
    throw new Error(`User info storage accounting failed: ${JSON.stringify(userMeJson)}`);
  }
  console.log("[16/18] GET /api/user/me -> ok");

  const delVaultRes = await fetch(
    `${BASE_URL}/api/vaults/my-personal-vault`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const delVaultJson = await delVaultRes.json();
  console.log("[17/18] DELETE /api/vaults/:name -> ok");

  const postDelVaultsRes = await fetch(`${BASE_URL}/api/vaults`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const postDelVaultsJson = await postDelVaultsRes.json();
  if (postDelVaultsJson.vaults.some((v) => v.name === "my-personal-vault")) {
    throw new Error(
      `Vault still returned in GET /api/vaults after deletion: ${JSON.stringify(postDelVaultsJson)}`
    );
  }
  console.log("[18/18] GET /api/vaults (absent check) -> ok");

  // Multi-user collaboration tests
  // 19. Alice creates a collaboration vault
  const createCollabRes = await fetch(`${BASE_URL}/api/vaults`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name: "collab-vault" }),
  });
  const createCollabJson = await createCollabRes.json();
  if (!createCollabJson.ok) throw new Error("Failed to create collab vault");
  console.log("[19/25] POST /api/vaults (collab-vault) -> ok");

  // 20. Bob registers
  const bobVerifier = "b".repeat(64);
  const bobRegRes = await fetch(`${BASE_URL}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "bob", verifier: bobVerifier }),
  });
  const bobRegJson = await bobRegRes.json();
  if (!bobRegJson.ok || !bobRegJson.token) throw new Error("Failed to register Bob");
  const bobToken = bobRegJson.token;
  console.log("[20/25] POST /api/auth/register (user: bob) -> ok");

  // 21. Alice invites Bob to collab-vault
  const inviteRes = await fetch(`${BASE_URL}/api/sync/shares?vault=collab-vault`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ inviteUsername: "bob" }),
  });
  const inviteJson = await inviteRes.json();
  if (!inviteJson.ok || !inviteJson.shares.includes("bob")) {
    throw new Error(`Invite failed: ${JSON.stringify(inviteJson)}`);
  }
  console.log("[21/25] POST /api/sync/shares (invite bob) -> ok");

  // 22. Bob lists vaults, sees collab-vault as shared
  const bobVaultsRes = await fetch(`${BASE_URL}/api/vaults`, {
    headers: { Authorization: `Bearer ${bobToken}` },
  });
  const bobVaultsJson = await bobVaultsRes.json();
  const sharedVault = bobVaultsJson.vaults.find((v) => v.name === "collab-vault");
  if (!sharedVault || !sharedVault.isShared || sharedVault.owner !== "alice") {
    throw new Error(`Bob did not find shared vault: ${JSON.stringify(bobVaultsJson)}`);
  }
  console.log("[22/25] GET /api/vaults (Bob sees shared vault from Alice) -> ok");

  // 23. Bob uploads a note to Alice's shared vault
  const bobPutRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=collab-vault&owner=alice&key=Team/BobNote.md`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${bobToken}`,
        "Content-Type": "text/markdown",
      },
      body: "# Collaboration Note\nWritten by Bob.",
    }
  );
  const bobPutJson = await bobPutRes.json();
  if (!bobPutJson.ok) throw new Error(`Bob put failed: ${JSON.stringify(bobPutJson)}`);

  // Alice reads Bob's note from her vault
  const aliceGetRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=collab-vault&key=Team/BobNote.md`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  if (aliceGetRes.status !== 200) {
    throw new Error(`Alice cannot read Bob's note: ${aliceGetRes.status}`);
  }
  const noteContent = await aliceGetRes.text();
  if (!noteContent.includes("Written by Bob")) {
    throw new Error(`Unexpected note content: ${noteContent}`);
  }
  console.log("[23/25] PUT & GET /api/sync/file (Bob writes, Alice reads) -> ok");

  // 24. Alice revokes Bob's access
  const removeRes = await fetch(
    `${BASE_URL}/api/sync/shares?vault=collab-vault&username=bob`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const removeJson = await removeRes.json();
  if (!removeJson.ok || removeJson.shares.includes("bob")) {
    throw new Error("Failed to remove Bob from shares");
  }
  console.log("[24/25] DELETE /api/sync/shares (revoke bob) -> ok");

  // 25. Bob attempts to access collab-vault, receives 403 Forbidden
  const bobForbiddenRes = await fetch(
    `${BASE_URL}/api/sync/file?vault=collab-vault&owner=alice&key=Team/BobNote.md`,
    {
      headers: { Authorization: `Bearer ${bobToken}` },
    }
  );
  if (bobForbiddenRes.status !== 403) {
    throw new Error(`Expected 403 Forbidden for revoked user, got: ${bobForbiddenRes.status}`);
  }
  console.log("[25/25] GET /api/sync/file (revoked user gets 403 Forbidden) -> ok");

  // 26. Avatar upload (Alice uploads valid PNG under 512KB)
  const validPng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==",
    "base64"
  );
  const avatarUploadRes = await fetch(`${BASE_URL}/api/user/avatar`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "image/png",
    },
    body: validPng,
  });
  const avatarUploadJson = await avatarUploadRes.json();
  if (avatarUploadRes.status !== 200 || !avatarUploadJson.ok) {
    throw new Error(`Avatar upload failed: status ${avatarUploadRes.status} ${JSON.stringify(avatarUploadJson)}`);
  }
  console.log("[26/30] POST /api/user/avatar (Alice uploads valid PNG under 512KB) -> ok");

  // 27. GET /api/user/avatar/alice returns 200 with image/png and nosniff
  const avatarGetRes = await fetch(`${BASE_URL}/api/user/avatar/alice`);
  if (avatarGetRes.status !== 200) {
    throw new Error(`Avatar GET failed: status ${avatarGetRes.status}`);
  }
  const avatarContentType = avatarGetRes.headers.get("content-type");
  const nosniffHeader = avatarGetRes.headers.get("x-content-type-options");
  if (!avatarContentType?.includes("image/png") || nosniffHeader !== "nosniff") {
    throw new Error(`Avatar headers incorrect: Content-Type=${avatarContentType}, nosniff=${nosniffHeader}`);
  }
  console.log("[27/30] GET /api/user/avatar/alice -> ok (image/png + nosniff)");

  // 28. POST /api/user/avatar with payload > 512KB rejected with 413 Payload Too Large
  const oversizedPayload = Buffer.alloc(513 * 1024);
  const oversizedRes = await fetch(`${BASE_URL}/api/user/avatar`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "image/png",
    },
    body: oversizedPayload,
  });
  if (oversizedRes.status !== 413) {
    throw new Error(`Expected 413 for oversized avatar, got: ${oversizedRes.status}`);
  }
  console.log("[28/30] POST /api/user/avatar (>512KB rejected with 413 Payload Too Large) -> ok");

  // 29. POST /api/user/avatar with non-image / SVG / script payload rejected with 400
  const unsafePayload = Buffer.from("<svg onload=alert(1)>unsafe</svg>");
  const unsafeRes = await fetch(`${BASE_URL}/api/user/avatar`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "image/svg+xml",
    },
    body: unsafePayload,
  });
  if (unsafeRes.status !== 400) {
    throw new Error(`Expected 400 for unsafe payload, got: ${unsafeRes.status}`);
  }
  console.log("[29/30] POST /api/user/avatar (unsafe format rejected with 400 Bad Request) -> ok");

  // 30. DELETE /api/user/avatar removes avatar and subsequent GET returns 404
  const delAvatarRes = await fetch(`${BASE_URL}/api/user/avatar`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  const delAvatarJson = await delAvatarRes.json();
  if (delAvatarRes.status !== 200 || !delAvatarJson.ok) {
    throw new Error(`Avatar delete failed: ${JSON.stringify(delAvatarJson)}`);
  }
  const postDelAvatarGet = await fetch(`${BASE_URL}/api/user/avatar/alice`);
  if (postDelAvatarGet.status !== 404) {
    throw new Error(`Expected 404 after avatar deletion, got: ${postDelAvatarGet.status}`);
  }
  console.log("[30/30] DELETE /api/user/avatar & verified 404 on subsequent GET -> ok");

  // 31. POST /api/user/profile updates Alice's display name
  const setProfileRes = await fetch(`${BASE_URL}/api/user/profile`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ displayName: "Alice Wonderland" }),
  });
  const setProfileJson = await setProfileRes.json();
  if (!setProfileJson.ok || setProfileJson.displayName !== "Alice Wonderland") {
    throw new Error(`Profile update failed: ${JSON.stringify(setProfileJson)}`);
  }
  console.log("[31/32] POST /api/user/profile (Alice sets display name) -> ok");

  // 32. GET /api/user/profile/alice returns public profile with displayName
  const getProfileRes = await fetch(`${BASE_URL}/api/user/profile/alice`);
  const getProfileJson = await getProfileRes.json();
  if (!getProfileJson.ok || getProfileJson.displayName !== "Alice Wonderland") {
    throw new Error(`Public profile fetch failed: ${JSON.stringify(getProfileJson)}`);
  }
  console.log("[32/32] GET /api/user/profile/alice -> ok (displayName verified)");

  // Clean up collab-vault
  await fetch(`${BASE_URL}/api/vaults/collab-vault`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });

  console.log("\nall 32 vps endpoint tests passed");
}

runTests()
  .then(() => {
    serverProc.kill("SIGTERM");
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
    process.exit(0);
  })
  .catch((err) => {
    console.error("\ntest failed:", err);
    serverProc.kill("SIGTERM");
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
    process.exit(1);
  });
