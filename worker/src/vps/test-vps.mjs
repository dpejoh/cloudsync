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

  console.log("\nall 18 vps endpoint tests passed");
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
