import type { CloudSyncConfig } from "../src/baseTypes";
import { AccountKeyManager, type KeyManagerResponse } from "../src/keyManager";

class FakeServer {
  users = new Map<string, any>();
  keyMaterial = new Map<string, any>();
  pubkeys = new Map<string, any>();
  envelopes = new Map<string, any>();
  tokens = new Map<string, string>();
  private nextId = 1;

  private newToken(userId: string): string {
    const token = `token-${userId}-${Math.random().toString(36).slice(2)}`;
    this.tokens.set(token, userId);
    return token;
  }

  private userFrom(token?: string): any | null {
    if (!token) return null;
    const userId = this.tokens.get(token);
    if (!userId) return null;
    if (userId === "default") {
      return { id: "default", username: "Owner", scheme: 2 };
    }
    for (const user of this.users.values()) if (user.id === userId) return user;
    return null;
  }

  private json(status: number, body: any): KeyManagerResponse {
    return { status, json: body, text: JSON.stringify(body) };
  }

  request = async (path: string, opts: any = {}): Promise<KeyManagerResponse> => {
    const method = opts.method ?? "GET";
    const url = new URL(`http://fake${path}`);
    const route = url.pathname;

    const paramsMatch = route.match(/^\/api\/auth\/params\/([^/]+)$/);
    if (method === "GET" && paramsMatch) {
      const username = decodeURIComponent(paramsMatch[1]).toLowerCase();
      const lookup = username === "default" ? "owner" : username;
      const user = this.users.get(lookup);
      const km = user ? this.keyMaterial.get(user.id) : null;
      if (user && user.scheme === 2 && km) {
        return this.json(200, { ok: true, scheme: 2, kdf: km.kdf });
      }
      return this.json(200, { ok: true, scheme: 1, kdf: null });
    }

    if (method === "POST" && route === "/api/auth/register") {
      const username = String(opts.body.username).toLowerCase();
      if (this.users.has(username)) return this.json(409, { error: "Username already taken." });
      const id = `user-${this.nextId++}`;
      this.users.set(username, {
        id,
        username: opts.body.username,
        verifier: opts.body.verifier,
        recoveryVerifier: opts.body.recoveryVerifier,
        scheme: opts.body.scheme,
      });
      return this.json(200, { ok: true, token: this.newToken(id), user: { id, username: opts.body.username } });
    }

    if (method === "POST" && route === "/api/auth/single-login") {
      if (typeof opts.body?.verifier !== "string" || opts.body.verifier.length !== 64) {
        return this.json(400, { error: "Valid 64-character password verifier required." });
      }
      return this.json(200, {
        ok: true,
        token: this.newToken("default"),
        user: { id: "default", username: "Owner" },
      });
    }

    if (method === "POST" && route === "/api/auth/login") {
      const username = String(opts.body.username).toLowerCase();
      const user = this.users.get(username);
      if (!user || user.verifier !== opts.body.verifier) {
        return this.json(401, { error: "Invalid username or password." });
      }
      return this.json(200, { ok: true, token: this.newToken(user.id), user: { id: user.id, username: user.username } });
    }

    if (method === "POST" && route === "/api/auth/recover") {
      const username = String(opts.body.username).toLowerCase();
      const user = this.users.get(username);
      if (!user || user.recoveryVerifier !== opts.body.recoveryVerifier) {
        return this.json(401, { error: "Invalid recovery key." });
      }
      user.verifier = opts.body.newVerifier;
      return this.json(200, { ok: true, token: this.newToken(user.id), user: { id: user.id, username: user.username } });
    }

    if (method === "POST" && route === "/api/user/recovery-key") {
      const user = this.userFrom(opts.token);
      if (!user) return this.json(401, { error: "Unauthorized" });
      user.recoveryVerifier = opts.body.recoveryVerifier;
      return this.json(200, { ok: true });
    }

    if (method === "POST" && route === "/api/user/change-password") {
      const user = this.userFrom(opts.token);
      if (!user || user.verifier !== opts.body.oldVerifier) {
        return this.json(401, { error: "Incorrect current password." });
      }
      user.verifier = opts.body.newVerifier;
      return this.json(200, { ok: true, token: this.newToken(user.id) });
    }

    if (route === "/api/user/keymaterial") {
      const user = this.userFrom(opts.token);
      if (!user) return this.json(401, { error: "Unauthorized" });
      if (method === "GET") {
        return this.json(200, { ok: true, keyMaterial: this.keyMaterial.get(user.id) ?? null });
      }
      if (method === "PUT") {
        const km = opts.body.keyMaterial;
        const existing = this.keyMaterial.get(user.id);
        if (existing && km.rev <= existing.rev) return this.json(409, { error: "Stale key material revision." });
        this.keyMaterial.set(user.id, km);
        this.pubkeys.set(user.username.toLowerCase(), {
          username: user.username.toLowerCase(),
          userId: user.id,
          publicKey: km.identity.publicKey,
        });
        return this.json(200, { ok: true, rev: km.rev });
      }
    }

    const pubMatch = route.match(/^\/api\/user\/pubkey\/([^/]+)$/);
    if (method === "GET" && pubMatch) {
      const record = this.pubkeys.get(decodeURIComponent(pubMatch[1]).toLowerCase());
      if (!record) return this.json(404, { error: "No public key for this user." });
      return this.json(200, { ok: true, ...record });
    }

    const envMatch = route.match(/^\/api\/vaults\/([^/]+)\/envelope\/([^/]+)$/);
    if (method === "PUT" && envMatch) {
      const owner = this.userFrom(opts.token);
      if (!owner) return this.json(401, { error: "Unauthorized" });
      const recipientUsername = decodeURIComponent(envMatch[2]).toLowerCase();
      const recipientRecord = this.pubkeys.get(recipientUsername);
      if (!recipientRecord) return this.json(404, { error: "Recipient not found." });
      const envelope = opts.body.envelope;
      if (envelope.recipientId !== recipientRecord.userId) return this.json(400, { error: "Bad recipient." });
      this.envelopes.set(`${owner.id}:${envMatch[1]}:${recipientRecord.userId}`, envelope);
      return this.json(200, { ok: true });
    }

    if (method === "GET" && /^\/api\/vaults\/[^/]+\/envelope$/.test(route)) {
      const caller = this.userFrom(opts.token);
      if (!caller) return this.json(401, { error: "Unauthorized" });
      const ownerName = (url.searchParams.get("owner") ?? "").toLowerCase();
      const owner = this.users.get(ownerName);
      if (!owner) return this.json(404, { error: "Owner not found." });
      const vault = route.split("/")[3];
      const envelope = this.envelopes.get(`${owner.id}:${vault}:${caller.id}`) ?? null;
      return this.json(200, { ok: true, envelope });
    }

    return this.json(404, { error: `no route ${method} ${route}` });
  };
}

function makeConfig(): CloudSyncConfig {
  return {
    serverUrl: "http://fake",
    username: "",
    token: "",
    vaultId: "",
    userId: "",
    mode: "multi",
  };
}

describe("AccountKeyManager", () => {
  it("registers, unlocks, and reports a recovery key", async () => {
    const server = new FakeServer();
    const config = makeConfig();
    const manager = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    const { recoveryKey } = await manager.register({ username: "alice", password: "pw-1" });
    expect(recoveryKey).toMatch(/^SYNC-/);
    expect(manager.isUnlocked).toBe(true);
    expect(config.scheme).toBe(2);
    expect(config.kdf?.alg).toBe("argon2id");
    expect(config.kek).toBeTruthy();
    expect(config.keyMaterial?.vaults).toEqual({});
  });

  it("logs in from a fresh device and rejects a wrong password", async () => {
    const server = new FakeServer();
    await new AccountKeyManager({
      transport: server,
      config: makeConfig(),
      persist: async () => {},
    }).register({ username: "alice", password: "pw-1" });

    const config2 = makeConfig();
    const manager2 = new AccountKeyManager({ transport: server, config: config2, persist: async () => {} });
    const result = await manager2.login({ username: "alice", password: "pw-1" });
    expect(result).toEqual({ ok: true });
    expect(manager2.isUnlocked).toBe(true);

    const manager3 = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await expect(manager3.login({ username: "alice", password: "wrong" })).rejects.toThrow();
  });

  it("unlocks from persisted session data", async () => {
    const server = new FakeServer();
    const config = makeConfig();
    const manager = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    await manager.register({ username: "alice", password: "pw-1" });

    const restored = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    expect(await restored.unlockFromCache()).toBe(true);
    expect(restored.isUnlocked).toBe(true);
    expect(restored.currentKeyMaterial?.accountId).toBe(config.userId);
  });

  it("shares a vault key via envelope and the collaborator opens it", async () => {
    const server = new FakeServer();
    const alice = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    const bob = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await alice.register({ username: "alice", password: "pw-a" });
    await bob.register({ username: "bob", password: "pw-b" });

    const vk = await alice.ensureOwnedVaultKey("vaultA");
    await alice.shareVaultKeyWith({ vaultId: "vaultA", version: 1, recipientUsername: "bob" });
    const opened = await bob.fetchSharedVaultKey({ vaultId: "vaultA", ownerUsername: "alice" });
    expect(opened).not.toBeNull();
    expect(opened!.version).toBe(1);
    expect(Buffer.from(opened!.vk)).toEqual(Buffer.from(vk));
    expect(Buffer.from((await bob.getVaultKey("vaultA"))!)).toEqual(Buffer.from(vk));
  });

  it("keeps vault keys through a password change", async () => {
    const server = new FakeServer();
    const config = makeConfig();
    const manager = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    await manager.register({ username: "alice", password: "old-pw" });
    const vk = await manager.ensureOwnedVaultKey("vaultA");

    await manager.changePassword({ oldPassword: "old-pw", newPassword: "new-pw" });
    expect(Buffer.from((await manager.getVaultKey("vaultA"))!)).toEqual(Buffer.from(vk));

    const fresh = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await expect(fresh.login({ username: "alice", password: "old-pw" })).rejects.toThrow();
    const result = await fresh.login({ username: "alice", password: "new-pw" });
    expect(result).toEqual({ ok: true });
    expect(Buffer.from((await fresh.getVaultKey("vaultA"))!)).toEqual(Buffer.from(vk));
  });

  it("keeps vault keys through recovery with the recovery key", async () => {
    const server = new FakeServer();
    const config = makeConfig();
    const manager = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    const { recoveryKey } = await manager.register({ username: "alice", password: "old-pw" });
    const vk = await manager.ensureOwnedVaultKey("vaultA");

    const fresh = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await fresh.recoverWithRecoveryKey({ username: "alice", recoveryKey, newPassword: "reset-pw" });
    expect(Buffer.from((await fresh.getVaultKey("vaultA"))!)).toEqual(Buffer.from(vk));

    const loginAfter = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await loginAfter.login({ username: "alice", password: "reset-pw" });
    expect(Buffer.from((await loginAfter.getVaultKey("vaultA"))!)).toEqual(Buffer.from(vk));
  });

  it("derives integrity keys per vault", async () => {
    const server = new FakeServer();
    const manager = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await manager.register({ username: "alice", password: "pw" });
    const vkA = await manager.ensureOwnedVaultKey("vaultA");
    const vkB = await manager.ensureOwnedVaultKey("vaultB");
    const keyA = await manager.integrityKey("vaultA");
    const keyB = await manager.integrityKey("vaultB");
    expect(Buffer.from(keyA!)).not.toEqual(Buffer.from(keyB!));
    expect(Buffer.from(vkA)).not.toEqual(Buffer.from(vkB));
  });

  it("enables a new recovery key on an existing v2 account", async () => {
    const server = new FakeServer();
    const manager = new AccountKeyManager({
      transport: server,
      config: makeConfig(),
      persist: async () => {},
    });
    await manager.register({ username: "alice", password: "pw-1" });
    const vk = await manager.ensureOwnedVaultKey("vaultA");
    await manager.enableRecoveryKey("SYNC-ABCD-EFGH-IJKL-MNOP-QRST-UVWX");

    const fresh = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await fresh.recoverWithRecoveryKey({
      username: "alice",
      recoveryKey: "SYNC-ABCD-EFGH-IJKL-MNOP-QRST-UVWX",
      newPassword: "pw-2",
    });
    expect(Buffer.from((await fresh.getVaultKey("vaultA"))!)).toEqual(Buffer.from(vk));
  });

  it("uses the v2 key model in single-user mode", async () => {
    const server = new FakeServer();
    const config = makeConfig();
    config.mode = "single";
    const manager = new AccountKeyManager({ transport: server, config, persist: async () => {} });

    const result = await manager.loginSingle({ password: "master-password" });
    expect(result.legacy).toBe(false);
    expect(manager.isUnlocked).toBe(true);
    expect(config.scheme).toBe(2);
    const vk = await manager.ensureOwnedVaultKey("vaultS");

    const fresh = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    const second = await fresh.loginSingle({ password: "master-password" });
    expect(second.legacy).toBe(false);
    expect(Buffer.from((await fresh.getVaultKey("vaultS"))!)).toEqual(Buffer.from(vk));
  });

  it("derives deterministic rotation keys", async () => {
    const server = new FakeServer();
    const manager = new AccountKeyManager({ transport: server, config: makeConfig(), persist: async () => {} });
    await manager.register({ username: "alice", password: "pw" });
    const a = await manager.deriveRotationKey("vaultA", 2);
    const b = await manager.deriveRotationKey("vaultA", 2);
    const c = await manager.deriveRotationKey("vaultA", 3);
    const d = await manager.deriveRotationKey("vaultB", 2);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
    expect(Buffer.from(a)).not.toEqual(Buffer.from(c));
    expect(Buffer.from(a)).not.toEqual(Buffer.from(d));
  });

  it("refuses rolled-back key material from the server", async () => {
    const server = new FakeServer();
    const registered = new AccountKeyManager({
      transport: server,
      config: makeConfig(),
      persist: async () => {},
    });
    await registered.register({ username: "alice", password: "pw" });
    const stored = [...server.keyMaterial.values()][0];

    const config = makeConfig();
    config.keyMaterial = { ...stored, rev: stored.rev + 10 };
    const victim = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    await expect(victim.login({ username: "alice", password: "pw" })).rejects.toThrow(/outdated/i);
  });

  it("clears secrets on logout", async () => {
    const server = new FakeServer();
    const config = makeConfig();
    const manager = new AccountKeyManager({ transport: server, config, persist: async () => {} });
    await manager.register({ username: "alice", password: "pw" });
    await manager.logout();
    expect(manager.isUnlocked).toBe(false);
    expect(config.token).toBe("");
    expect(config.kek).toBeUndefined();
    expect(config.keyMaterial).toBeUndefined();
  });
});
