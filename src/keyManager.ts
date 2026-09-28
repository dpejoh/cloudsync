/**
 * Runtime key management for protocol v2 accounts.
 *
 * Secrets (master key, identity private key, vault keys) live only in memory.
 * `data.json` keeps the wrapped key material, the KDF descriptor and the KEK so
 * the plugin can unlock after a restart without re-entering the password.
 */
import { deriveRecoveryVerifier, deriveZeroKnowledgeKeys } from "./authHelper";
import type { CloudSyncConfig } from "./baseTypes";
import {
  type AccountKeyMaterial,
  CRYPTO_V2_PROTOCOL,
  type KdfDescriptor,
  type VaultKeyEnvelope,
  createKeyMaterialWithKek,
  deriveAccountKeys,
  deriveIntegrityKey,
  deriveRecoveryKek,
  deriveVaultRotationKey,
  generateRecoveryKey,
  generateSymmetricKey,
  getVaultKey,
  hexDecode,
  hexEncode,
  macKeyMaterial,
  newKdfDescriptor,
  newRecoverySalt,
  openVaultKeyEnvelope,
  rewrapKeyMaterial,
  rewrapKeyMaterialFromRecovery,
  sealVaultKeyForRecipient,
  unlockKeyMaterial,
  verifyKeyMaterialMac,
  withVaultKey,
  withoutVaultKey,
  wrapMasterKey,
} from "./cryptoV2";

export interface KeyManagerResponse {
  status: number;
  json?: any;
  text?: string;
  headers?: Record<string, string>;
  arrayBuffer?: ArrayBuffer;
}

export interface KeyManagerTransport {
  request(
    path: string,
    opts?: {
      method?: string;
      token?: string;
      body?: any;
      headers?: Record<string, string>;
    }
  ): Promise<KeyManagerResponse>;
}

export interface KeyManagerOptions {
  transport: KeyManagerTransport;
  config: CloudSyncConfig;
  persist: () => Promise<void>;
}

export type LoginResult =
  | { ok: true }
  | { requires2FA: true }
  | { legacy: true };

export class AccountKeyManager {
  private transport: KeyManagerTransport;
  private config: CloudSyncConfig;
  private persist: () => Promise<void>;

  private masterKey?: Uint8Array;
  private identityPrivateKey?: Uint8Array;
  private kekBytes?: Uint8Array;
  private keyMaterial?: AccountKeyMaterial;
  private vaultKeyCache = new Map<string, Uint8Array>();
  private integrityKeyCache = new Map<string, Uint8Array>();

  /** True when legacy (pre-v2) account keys are being used. */
  legacyMode = false;

  constructor(opts: KeyManagerOptions) {
    this.transport = opts.transport;
    this.config = opts.config;
    this.persist = opts.persist;
  }

  get isUnlocked(): boolean {
    return this.masterKey !== undefined && this.keyMaterial !== undefined;
  }

  get currentKeyMaterial(): AccountKeyMaterial | undefined {
    return this.keyMaterial;
  }

  get currentKdf(): KdfDescriptor | undefined {
    return this.config.kdf;
  }

  // Session helpers

  private normalizeUsername(username: string): string {
    return username.trim().toLowerCase();
  }

  private async fetchParams(
    username: string
  ): Promise<{ scheme: 1 | 2; kdf: KdfDescriptor | null }> {
    const res = await this.transport.request(
      `/api/auth/params/${encodeURIComponent(this.normalizeUsername(username))}`
    );
    if (res.status !== 200 || !res.json) {
      return { scheme: 1, kdf: null };
    }
    return {
      scheme: res.json.scheme === 2 ? 2 : 1,
      kdf: res.json.kdf ?? null,
    };
  }

  /** Protocol scheme of an account, without authenticating. */
  async accountScheme(username: string): Promise<1 | 2> {
    try {
      const params = await this.fetchParams(username);
      return params.scheme;
    } catch {
      return 1;
    }
  }

  private async fetchKeyMaterial(
    token: string
  ): Promise<AccountKeyMaterial | null> {
    const res = await this.transport.request("/api/user/keymaterial", {
      token,
    });
    if (res.status !== 200 || !res.json?.keyMaterial) return null;
    return res.json.keyMaterial as AccountKeyMaterial;
  }

  private async putKeyMaterial(
    token: string,
    keyMaterial: AccountKeyMaterial
  ): Promise<boolean> {
    const res = await this.transport.request("/api/user/keymaterial", {
      method: "PUT",
      token,
      body: { keyMaterial },
    });
    if (res.status !== 200) return false;
    this.keyMaterial = keyMaterial;
    this.config.keyMaterial = keyMaterial;
    await this.persist();
    return true;
  }

  private async applySession(opts: {
    token: string;
    userId: string;
    username: string;
    kdf: KdfDescriptor;
    kek: Uint8Array;
    keyMaterial: AccountKeyMaterial;
  }): Promise<void> {
    const { masterKey, identityPrivateKey } = await unlockKeyMaterial(
      opts.keyMaterial,
      opts.kek
    );
    this.masterKey = masterKey;
    this.identityPrivateKey = identityPrivateKey;
    this.kekBytes = opts.kek;
    this.keyMaterial = opts.keyMaterial;
    this.vaultKeyCache.clear();
    this.integrityKeyCache.clear();
    this.legacyMode = false;

    this.config.token = opts.token;
    this.config.userId = opts.userId;
    this.config.username = opts.username;
    this.config.scheme = 2;
    this.config.kdf = opts.kdf;
    this.config.kek = hexEncode(opts.kek);
    this.config.keyMaterial = opts.keyMaterial;
    await this.persist();
  }

  /** Unlocks using already persisted session data (plugin restart). */
  async unlockFromCache(): Promise<boolean> {
    if (!this.config.token || !this.config.kek) return false;
    try {
      const km =
        this.config.keyMaterial ??
        (await this.fetchKeyMaterial(this.config.token));
      if (!km) return false;
      if (km.v !== CRYPTO_V2_PROTOCOL) return false;
      const kek = hexDecode(this.config.kek);
      if (!(await verifyKeyMaterialMac(km, kek))) {
        this.clearSecrets();
        return false;
      }
      const { masterKey, identityPrivateKey } = await unlockKeyMaterial(
        km,
        kek
      );
      this.masterKey = masterKey;
      this.identityPrivateKey = identityPrivateKey;
      this.kekBytes = kek;
      this.keyMaterial = km;
      this.legacyMode = false;
      return true;
    } catch {
      return false;
    }
  }

  clearSecrets(): void {
    const wipe = (b?: Uint8Array) => {
      if (b) b.fill(0);
    };
    wipe(this.masterKey);
    wipe(this.identityPrivateKey);
    wipe(this.kekBytes);
    this.masterKey = undefined;
    this.identityPrivateKey = undefined;
    this.kekBytes = undefined;
    this.keyMaterial = undefined;
    this.vaultKeyCache.clear();
    this.integrityKeyCache.clear();
  }

  /** Clears session data from settings (logout). */
  async logout(): Promise<void> {
    this.clearSecrets();
    this.config.token = "";
    this.config.userId = "";
    this.config.username = "";
    this.config.displayName = "";
    this.config.email = "";
    this.config.scheme = undefined;
    this.config.kdf = undefined;
    this.config.kek = undefined;
    this.config.keyMaterial = undefined;
    this.config.sessionExpired = false;
    await this.persist();
  }

  // Account flows

  async register(opts: { username: string; password: string }): Promise<{
    recoveryKey: string;
  }> {
    const username = opts.username.trim();
    const kdf = newKdfDescriptor();
    const { kek, authVerifier } = await deriveAccountKeys(
      opts.password,
      kdf,
      username
    );
    const recoveryKey = generateRecoveryKey();
    const recoveryVerifier = await deriveRecoveryVerifier(recoveryKey);

    const res = await this.transport.request("/api/auth/register", {
      method: "POST",
      body: { username, verifier: authVerifier, recoveryVerifier, scheme: 2 },
    });
    if (res.status !== 200 || !res.json?.token) {
      throw new Error(res.json?.error || "Registration failed.");
    }
    const { token, user } = res.json;

    const { keyMaterial } = await createKeyMaterialWithKek({
      accountId: user.id,
      username,
      kek,
      kdf,
      recoveryKey,
    });
    const stored = await this.putKeyMaterial(token, keyMaterial);
    if (!stored) {
      throw new Error(
        "Account created, but storing the encryption keys failed. Please log in and retry."
      );
    }

    this.config.recoveryKey = recoveryKey;
    await this.applySession({
      token,
      userId: user.id,
      username,
      kdf,
      kek,
      keyMaterial,
    });
    return { recoveryKey };
  }

  async login(opts: {
    username: string;
    password: string;
    totpCode?: string;
  }): Promise<LoginResult> {
    const username = opts.username.trim();
    const params = await this.fetchParams(username);
    if (params.scheme !== 2 || !params.kdf) {
      return { legacy: true };
    }
    const kdf = params.kdf;
    const { kek, authVerifier } = await deriveAccountKeys(
      opts.password,
      kdf,
      username
    );

    const res = await this.transport.request("/api/auth/login", {
      method: "POST",
      body: { username, verifier: authVerifier, totpCode: opts.totpCode },
    });
    if (res.json?.requires2FA) {
      return { requires2FA: true };
    }
    if (res.status !== 200 || !res.json?.token) {
      throw new Error(res.json?.error || "Invalid username or password.");
    }
    const { token, user } = res.json;
    const keyMaterial = await this.fetchKeyMaterial(token);
    if (!keyMaterial) {
      throw new Error(
        "This account has no encryption keys stored yet. If it is an older account, use the migration flow."
      );
    }
    const cached = this.config.keyMaterial;
    if (
      cached &&
      cached.accountId === keyMaterial.accountId &&
      keyMaterial.rev < cached.rev
    ) {
      throw new Error(
        "The server returned outdated encryption keys. Refusing to continue."
      );
    }
    await this.applySession({
      token,
      userId: user.id,
      username: user.username ?? username,
      kdf,
      kek,
      keyMaterial,
    });
    return { ok: true };
  }

  /**
   * Single-user mode. The login verifier stays PBKDF2-based because the server
   * must be able to check SINGLE_USER_PASSWORD without Argon2 (free Worker CPU
   * limits); the encryption keys use the v2 master-key/vault-key model.
   */
  async loginSingle(opts: { password: string }): Promise<{ legacy: boolean }> {
    const { authVerifier } = await deriveZeroKnowledgeKeys(
      "default",
      opts.password
    );
    const res = await this.transport.request("/api/auth/single-login", {
      method: "POST",
      body: { verifier: authVerifier },
    });
    if (res.status !== 200 || !res.json?.token) {
      throw new Error(res.json?.error || "Invalid master password.");
    }
    const token = res.json.token as string;
    const userId = res.json.user?.id || "default";
    const username = res.json.user?.username || "Owner";

    const keyMaterial = await this.fetchKeyMaterial(token);
    if (!keyMaterial) {
      const kdf = newKdfDescriptor();
      const { kek } = await deriveAccountKeys(opts.password, kdf, "default");
      const created = await createKeyMaterialWithKek({
        accountId: userId,
        username,
        kek,
        kdf,
      });
      const stored = await this.putKeyMaterial(token, created.keyMaterial);
      if (!stored) throw new Error("Failed to store the account keys.");
      await this.applySession({
        token,
        userId,
        username,
        kdf,
        kek,
        keyMaterial: created.keyMaterial,
      });
      return { legacy: false };
    }

    const { kek } = await deriveAccountKeys(
      opts.password,
      keyMaterial.kdf,
      "default"
    );
    await this.applySession({
      token,
      userId,
      username,
      kdf: keyMaterial.kdf,
      kek,
      keyMaterial,
    });
    return { legacy: false };
  }

  async recoverWithRecoveryKey(opts: {
    username: string;
    recoveryKey: string;
    newPassword: string;
  }): Promise<void> {
    const username = opts.username.trim();
    const newKdf = newKdfDescriptor();
    const { kek: newKek, authVerifier: newVerifier } = await deriveAccountKeys(
      opts.newPassword,
      newKdf,
      username
    );
    const recoveryVerifier = await deriveRecoveryVerifier(opts.recoveryKey);

    const res = await this.transport.request("/api/auth/recover", {
      method: "POST",
      body: { username, recoveryVerifier, newVerifier },
    });
    if (res.status !== 200 || !res.json?.token) {
      throw new Error(res.json?.error || "Recovery failed.");
    }
    const { token, user } = res.json;
    const keyMaterial = await this.fetchKeyMaterial(token);
    if (!keyMaterial) {
      throw new Error("No encryption keys found for this account.");
    }
    const rewrapped = await rewrapKeyMaterialFromRecovery(
      keyMaterial,
      opts.recoveryKey,
      newKek,
      newRecoverySalt(),
      newKdf
    );
    const stored = await this.putKeyMaterial(token, rewrapped);
    if (!stored) {
      throw new Error(
        "Password changed, but storing the re-wrapped encryption keys failed."
      );
    }
    this.config.recoveryKey = opts.recoveryKey;
    await this.applySession({
      token,
      userId: user.id,
      username,
      kdf: newKdf,
      kek: newKek,
      keyMaterial: rewrapped,
    });
  }

  /**
   * Recovery through TOTP only: the server lets the user in, but the master key
   * cannot be unwrapped, so existing encrypted vaults stay inaccessible.
   */
  async recoverWithTotp(opts: {
    username: string;
    totpCode: string;
    newPassword: string;
  }): Promise<void> {
    const username = opts.username.trim();
    const newKdf = newKdfDescriptor();
    const { authVerifier: newVerifier } = await deriveAccountKeys(
      opts.newPassword,
      newKdf,
      username
    );
    const res = await this.transport.request("/api/auth/recover", {
      method: "POST",
      body: { username, totpCode: opts.totpCode, newVerifier },
    });
    if (res.status !== 200 || !res.json?.token) {
      throw new Error(res.json?.error || "Recovery failed.");
    }
    this.clearSecrets();
    this.config.token = res.json.token;
    this.config.userId = res.json.user?.id || "";
    this.config.username = res.json.user?.username ?? username;
    this.config.scheme = 2;
    this.config.kdf = newKdf;
    this.config.kek = undefined;
    this.config.keyMaterial = undefined;
    await this.persist();
  }

  async changePassword(opts: {
    oldPassword: string;
    newPassword: string;
  }): Promise<void> {
    const config = this.config;
    const kdf = config.kdf;
    const token = config.token;
    const username = config.username;
    if (!kdf || !token || !username) {
      throw new Error("Not signed in with a protocol v2 account.");
    }
    const oldVerifier = (
      await deriveAccountKeys(opts.oldPassword, kdf, username)
    ).authVerifier;
    const newKdf = newKdfDescriptor();
    const { kek: newKek, authVerifier: newVerifier } = await deriveAccountKeys(
      opts.newPassword,
      newKdf,
      username
    );

    const res = await this.transport.request("/api/user/change-password", {
      method: "POST",
      token,
      body: { oldVerifier, newVerifier },
    });
    if (res.status !== 200 || !res.json?.token) {
      throw new Error(res.json?.error || "Password change failed.");
    }
    const newToken = res.json.token as string;
    const km = this.keyMaterial ?? config.keyMaterial;
    if (!km || !this.kekBytes) {
      throw new Error(
        "Password changed, but the encryption keys are locked on this device."
      );
    }
    const rewrapped = await rewrapKeyMaterial(
      km,
      this.kekBytes,
      newKek,
      newKdf
    );
    const stored = await this.putKeyMaterial(newToken, rewrapped);
    if (!stored) {
      throw new Error(
        "Password changed, but storing the re-wrapped encryption keys failed."
      );
    }
    await this.applySession({
      token: newToken,
      userId: config.userId,
      username,
      kdf: newKdf,
      kek: newKek,
      keyMaterial: rewrapped,
    });
  }

  // Vault keys

  private async storeOwnVaultKey(
    vaultId: string,
    version: number,
    vk: Uint8Array
  ): Promise<void> {
    if (!this.keyMaterial || !this.kekBytes)
      throw new Error("Account is locked.");
    this.keyMaterial = await withVaultKey(
      this.keyMaterial,
      this.kekBytes,
      vaultId,
      version,
      vk
    );
    this.config.keyMaterial = this.keyMaterial;
    const stored = await this.putKeyMaterial(
      this.config.token,
      this.keyMaterial
    );
    if (!stored)
      throw new Error("Failed to store the vault key on the server.");
    this.vaultKeyCache.set(vaultId, vk);
    this.integrityKeyCache.delete(vaultId);
  }

  /** Returns the vault key for an owned/shared vault, or null when none exists. */
  async getVaultKey(vaultId: string): Promise<Uint8Array | null> {
    const cached = this.vaultKeyCache.get(vaultId);
    if (cached) return cached;
    if (!this.keyMaterial || !this.masterKey) return null;
    const entry = await getVaultKey(this.keyMaterial, this.masterKey, vaultId);
    if (!entry) return null;
    this.vaultKeyCache.set(vaultId, entry.vk);
    return entry.vk;
  }

  /** Creates a random vault key when missing (new vaults, first connect). */
  async ensureOwnedVaultKey(vaultId: string): Promise<Uint8Array> {
    const existing = await this.getVaultKey(vaultId);
    if (existing) return existing;
    const vk = generateSymmetricKey();
    await this.storeOwnVaultKey(vaultId, 1, vk);
    return vk;
  }

  vaultKeyVersion(vaultId: string): number | undefined {
    return this.keyMaterial?.vaults[vaultId]?.version;
  }

  /** Stores a specific owned vault key/version (used by rotation). */
  async setOwnedVaultKey(
    vaultId: string,
    version: number,
    vk: Uint8Array
  ): Promise<void> {
    await this.storeOwnVaultKey(vaultId, version, vk);
  }

  /** Deterministic new key for a re-key attempt (retry-safe). */
  async deriveRotationKey(
    vaultId: string,
    version: number
  ): Promise<Uint8Array> {
    if (!this.masterKey) throw new Error("Account is locked.");
    return await deriveVaultRotationKey(this.masterKey, vaultId, version);
  }

  /**
   * Resolves the key for a specific vault version. Version 1 is the original
   * random key (only available in the key material); later versions are always
   * produced by rotation and can be re-derived from the master key, which makes
   * an interrupted re-key recoverable even if the local copy was lost.
   */
  async vaultKeyForVersion(
    vaultId: string,
    version: number
  ): Promise<Uint8Array | null> {
    if (this.keyMaterial?.vaults[vaultId]?.version === version) {
      return await this.getVaultKey(vaultId);
    }
    if (version > 1) {
      try {
        return await this.deriveRotationKey(vaultId, version);
      } catch {
        return null;
      }
    }
    return null;
  }

  /**
   * Attaches (or replaces) the recovery key: registers the verifier with the
   * server and adds a recovery wrap of the master key to the key material.
   */
  async enableRecoveryKey(recoveryKey: string): Promise<void> {
    const km = this.keyMaterial ?? this.config.keyMaterial;
    if (!km || !this.kekBytes || !this.masterKey || !this.config.token) {
      throw new Error("Account is locked.");
    }
    const salt = newRecoverySalt();
    const recoveryKek = await deriveRecoveryKek(recoveryKey, salt);
    const wrapped = await wrapMasterKey(recoveryKek, this.masterKey);
    const next: AccountKeyMaterial = {
      ...km,
      recovery: { salt },
      wrappedMasterKeyRecovery: wrapped,
      rev: km.rev + 1,
      mac: "",
    };
    next.mac = await macKeyMaterial(next, this.kekBytes);

    const serverVerifier = await deriveRecoveryVerifier(recoveryKey);
    const res = await this.transport.request("/api/user/recovery-key", {
      method: "POST",
      token: this.config.token,
      body: { recoveryVerifier: serverVerifier },
    });
    if (res.status !== 200) {
      throw new Error(
        res.json?.error ||
          "Failed to register the recovery key with the server."
      );
    }
    const stored = await this.putKeyMaterial(this.config.token, next);
    if (!stored) {
      throw new Error("Failed to store the recovery key material.");
    }
    this.config.recoveryKey = recoveryKey;
    await this.persist();
  }

  // Collaboration and rotation plumbing

  async listCollaborators(vaultId: string): Promise<string[]> {
    const res = await this.transport.request(
      `/api/sync/shares?vault=${encodeURIComponent(vaultId)}`,
      { token: this.config.token, headers: { "x-rotation": "1" } }
    );
    if (res.status !== 200 || !Array.isArray(res.json?.shares)) return [];
    return res.json.shares as string[];
  }

  async getOwnedVaultState(vaultId: string): Promise<{
    keyVersion: number;
    rotating: boolean;
    rotatingBy?: string;
  }> {
    const res = await this.transport.request("/api/vaults", {
      token: this.config.token,
    });
    if (res.status !== 200 || !Array.isArray(res.json?.vaults)) {
      throw new Error("Could not read the vault state.");
    }
    const vault = res.json.vaults.find(
      (v: any) => v.name === vaultId && !v.isShared
    );
    if (!vault) throw new Error("Vault not found on this account.");
    return {
      keyVersion: typeof vault.keyVersion === "number" ? vault.keyVersion : 1,
      rotating: vault.rotating === true,
      rotatingBy: vault.rotatingBy,
    };
  }

  async beginRotation(
    vaultId: string,
    deviceId: string
  ): Promise<{ keyVersion: number }> {
    const res = await this.transport.request(
      `/api/vaults/${encodeURIComponent(vaultId)}/rotation`,
      {
        method: "POST",
        token: this.config.token,
        headers: { "x-device-id": deviceId },
        body: { action: "begin" },
      }
    );
    if (res.status !== 200)
      throw new Error(res.json?.error || "Could not start the key rotation.");
    return { keyVersion: res.json.keyVersion };
  }

  async commitRotation(
    vaultId: string,
    keyVersion: number,
    deviceId: string
  ): Promise<void> {
    const res = await this.transport.request(
      `/api/vaults/${encodeURIComponent(vaultId)}/rotation`,
      {
        method: "POST",
        token: this.config.token,
        headers: { "x-device-id": deviceId },
        body: { action: "commit", keyVersion },
      }
    );
    if (res.status !== 200)
      throw new Error(res.json?.error || "Could not finish the key rotation.");
  }

  async abortRotation(vaultId: string, deviceId: string): Promise<void> {
    const res = await this.transport.request(
      `/api/vaults/${encodeURIComponent(vaultId)}/rotation`,
      {
        method: "POST",
        token: this.config.token,
        headers: { "x-device-id": deviceId },
        body: { action: "abort" },
      }
    );
    if (res.status !== 200) {
      throw new Error(res.json?.error || "Could not cancel the key rotation.");
    }
  }

  async purgeVaultDerivatives(vaultId: string): Promise<void> {
    const res = await this.transport.request(
      `/api/vaults/${encodeURIComponent(vaultId)}/purge`,
      { method: "POST", token: this.config.token }
    );
    if (res.status !== 200)
      throw new Error(res.json?.error || "Could not purge old history/trash.");
  }

  setSharedVaultKey(vaultId: string, vk: Uint8Array): void {
    this.vaultKeyCache.set(vaultId, vk);
    this.integrityKeyCache.delete(vaultId);
  }

  async removeOwnedVaultKey(vaultId: string): Promise<void> {
    if (!this.keyMaterial || !this.kekBytes) return;
    this.keyMaterial = await withoutVaultKey(
      this.keyMaterial,
      this.kekBytes,
      vaultId
    );
    this.config.keyMaterial = this.keyMaterial;
    await this.putKeyMaterial(this.config.token, this.keyMaterial);
    this.vaultKeyCache.delete(vaultId);
    this.integrityKeyCache.delete(vaultId);
  }

  async integrityKey(vaultId: string): Promise<Uint8Array | null> {
    const cached = this.integrityKeyCache.get(vaultId);
    if (cached) return cached;
    const vk = await this.getVaultKey(vaultId);
    if (!vk) return null;
    const key = await deriveIntegrityKey(vk);
    this.integrityKeyCache.set(vaultId, key);
    return key;
  }

  // Sharing envelopes

  async fetchRecipientPublicKey(
    username: string
  ): Promise<{ userId: string; publicKey: string }> {
    const res = await this.transport.request(
      `/api/user/pubkey/${encodeURIComponent(username)}`,
      {
        token: this.config.token,
      }
    );
    if (res.status !== 200 || !res.json?.publicKey || !res.json?.userId) {
      throw new Error(
        res.json?.error ||
          "Recipient has no encryption keys yet. Ask them to sign in with an updated plugin."
      );
    }
    return { userId: res.json.userId, publicKey: res.json.publicKey };
  }

  /** Seals this vault's key to a collaborator and stores the envelope server-side. */
  async shareVaultKeyWith(opts: {
    vaultId: string;
    version: number;
    recipientUsername: string;
    vk?: Uint8Array;
  }): Promise<void> {
    const vk = opts.vk ?? (await this.ensureOwnedVaultKey(opts.vaultId));
    const recipient = await this.fetchRecipientPublicKey(
      opts.recipientUsername
    );
    const envelope = await sealVaultKeyForRecipient(vk, recipient.publicKey, {
      v: CRYPTO_V2_PROTOCOL,
      vaultId: opts.vaultId,
      keyVersion: opts.version,
      ownerId: this.config.userId,
      recipientId: recipient.userId,
    });
    const res = await this.transport.request(
      `/api/vaults/${encodeURIComponent(opts.vaultId)}/envelope/${encodeURIComponent(
        opts.recipientUsername
      )}`,
      { method: "PUT", token: this.config.token, body: { envelope } }
    );
    if (res.status !== 200) {
      throw new Error(
        res.json?.error || "Failed to store the shared vault key."
      );
    }
  }

  /** Fetches and opens the collaborator's envelope for a shared vault. */
  async fetchSharedVaultKey(opts: {
    vaultId: string;
    ownerUsername: string;
  }): Promise<{ version: number; vk: Uint8Array } | null> {
    const res = await this.transport.request(
      `/api/vaults/${encodeURIComponent(opts.vaultId)}/envelope?owner=${encodeURIComponent(
        opts.ownerUsername
      )}`,
      { token: this.config.token }
    );
    if (res.status !== 200 || !res.json?.envelope) return null;
    if (!this.identityPrivateKey) throw new Error("Account is locked.");
    const envelope = res.json.envelope as VaultKeyEnvelope;
    const vk = await openVaultKeyEnvelope(envelope, this.identityPrivateKey);
    this.setSharedVaultKey(opts.vaultId, vk);
    return { version: envelope.keyVersion, vk };
  }
}
