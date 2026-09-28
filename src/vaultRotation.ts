/**
 * Vault key rotation (revoking collaborators / invalidating a shared vault key).
 * Crash-safe: the local key advances only after the server commits, the new key
 * is derived deterministically so retries are idempotent, and every remote
 * object is classified by key generation before anything is rewritten or
 * deleted. Invariants and format constraints: docs/ARCHITECTURE.md.
 */
import PQueue from "p-queue";
import type { Entity } from "./baseTypes";
import { deriveIntegrityKey, vaultKeyToPassword } from "./cryptoV2";
import { FakeFsEncrypt } from "./fsEncrypt";
import { FakeFsWorker } from "./fsWorker";
import type CloudSyncPlugin from "./main";

export interface RotationResult {
  keyVersion: number;
  files: number;
  resumed: boolean;
}

const ROTATION_CONCURRENCY = 12;
const PURGE_BATCH_SIZE = 200;
const PURGE_CONCURRENCY = 4;

const plausiblePlainName = (name: string): boolean =>
  name.length > 0 && !/[\u0000-\u001f\uFFFD]/.test(name);

interface ActiveRotation {
  promise: Promise<RotationResult>;
  controller: { aborted: boolean; lastMessage: string };
  listeners: Set<(message: string) => void>;
}

const activeRotations = new Map<string, ActiveRotation>();

function rotationKey(plugin: CloudSyncPlugin, vaultId: string): string {
  return `${plugin.settings.cloudsync.serverUrl}|${vaultId}`;
}

export function rotateVaultKey(
  plugin: CloudSyncPlugin,
  vaultId: string,
  onProgress?: (message: string) => void
): Promise<RotationResult> {
  const key = rotationKey(plugin, vaultId);
  const existing = activeRotations.get(key);
  if (existing) {
    if (onProgress) {
      existing.listeners.add(onProgress);
      if (existing.controller.lastMessage) {
        try {
          onProgress(existing.controller.lastMessage);
        } catch {}
      }
    }
    return existing.promise;
  }
  if (plugin.isSyncing || plugin.isFastSyncing) {
    return Promise.reject(
      new Error("A sync is running. Wait for it to finish before re-keying.")
    );
  }
  // Set synchronously so no sync can start between this check and the first
  // network call; the server-side rotation lock only starts later.
  plugin.isRotating = true;
  const controller = { aborted: false, lastMessage: "" };
  const listeners = new Set<(message: string) => void>();
  if (onProgress) listeners.add(onProgress);
  const report = (message: string) => {
    controller.lastMessage = message;
    for (const listener of listeners) {
      try {
        listener(message);
      } catch {}
    }
  };
  const run = doRotate(
    plugin,
    vaultId,
    report,
    () => controller.aborted
  ).finally(() => {
    plugin.isRotating = false;
    activeRotations.delete(key);
  });
  activeRotations.set(key, { promise: run, controller, listeners });
  return run;
}

/** Stops a running re-key: marks it canceled and releases the server lock. */
export async function cancelVaultRotation(
  plugin: CloudSyncPlugin,
  vaultId: string
): Promise<void> {
  const entry = activeRotations.get(rotationKey(plugin, vaultId));
  if (entry) entry.controller.aborted = true;
  const deviceId = plugin.settings.deviceId || "unknown-device";
  await plugin.keyManager.abortRotation(vaultId, deviceId);
}

export function isVaultRotationRunning(
  plugin: CloudSyncPlugin,
  vaultId: string
): boolean {
  return activeRotations.has(rotationKey(plugin, vaultId));
}

async function doRotate(
  plugin: CloudSyncPlugin,
  vaultId: string,
  onProgress?: (message: string) => void,
  isAborted?: () => boolean
): Promise<RotationResult> {
  const throwIfAborted = () => {
    if (isAborted?.()) throw new Error("Re-key canceled.");
  };
  const km = plugin.keyManager;
  const cs = plugin.settings.cloudsync;
  if (cs.vaultId !== vaultId) {
    throw new Error("Connect to the vault before re-keying it.");
  }
  if (!km.isUnlocked) {
    throw new Error("The account is locked.");
  }
  const deviceId = plugin.settings.deviceId || "unknown-device";

  const state = await km.getOwnedVaultState(vaultId);
  const serverVersion = state.keyVersion;
  const localVersion = km.vaultKeyVersion(vaultId) ?? serverVersion;

  // Already committed; only the local key material needs to catch up.
  if (!state.rotating && localVersion < serverVersion) {
    onProgress?.("Recovering the committed vault key...");
    const committed = await km.vaultKeyForVersion(vaultId, serverVersion);
    if (!committed)
      throw new Error("Could not recover the committed vault key.");
    await km.setOwnedVaultKey(vaultId, serverVersion, committed);
    plugin.clearCachedClients();
    return { keyVersion: serverVersion, files: 0, resumed: true };
  }
  if (state.rotating && state.rotatingBy && state.rotatingBy !== deviceId) {
    throw new Error("A re-key is already running on another device.");
  }

  const newVersion = serverVersion + 1;
  const newVk = await km.deriveRotationKey(vaultId, newVersion);
  const oldVk =
    localVersion === serverVersion
      ? await km.vaultKeyForVersion(vaultId, serverVersion)
      : null;

  const { fsRemote } = await plugin.getOrCreateClients();
  const method = plugin.settings.encryptionMethod || "rclone-base64";
  // Reads use the old key/integrity; writes use the new one, so they need
  // separate clients (the integrity key lives on the remote instance).
  const writeRemote = new FakeFsWorker(fsRemote.config, fsRemote.vaultName);
  const oldIntegrityKey = oldVk ? await deriveIntegrityKey(oldVk) : undefined;
  const newIntegrityKey = await deriveIntegrityKey(newVk);
  fsRemote.setIntegrityKey(oldIntegrityKey);
  writeRemote.setIntegrityKey(newIntegrityKey);
  writeRemote.setKeyVersion(newVersion);
  const oldFs = oldVk
    ? new FakeFsEncrypt(fsRemote, vaultKeyToPassword(oldVk), method)
    : null;
  const newFs = new FakeFsEncrypt(
    writeRemote,
    vaultKeyToPassword(newVk),
    method
  );

  const tryDecryptName = async (
    fs: FakeFsEncrypt,
    rawKey: string
  ): Promise<string | null> => {
    try {
      const plain = await fs._decryptName(rawKey);
      return typeof plain === "string" && plausiblePlainName(plain)
        ? plain
        : null;
    } catch {
      return null;
    }
  };
  const readOldContent = async (
    plain: string,
    raw: string
  ): Promise<ArrayBuffer> => {
    if (!oldFs) throw new Error("The previous vault key is unavailable.");
    // Teach the old client the stored raw name (openssl names are randomized),
    // then read it: this verifies integrity and decrypts the content before the
    // new key re-encrypts it.
    oldFs.cacheMapOrigToEnc[plain] = raw;
    return await oldFs.readFile(plain);
  };

  const wasRotating = state.rotating;
  onProgress?.(
    wasRotating
      ? "Resuming vault re-key..."
      : "Preparing vault for re-keying..."
  );
  if (!wasRotating) {
    await km.beginRotation(vaultId, deviceId);
  }
  fsRemote.setRotationMode(true);
  writeRemote.setRotationMode(true);
  try {
    throwIfAborted();

    // Classify every remote object by key generation instead of walking with
    // the old key. This makes the rotation safe to resume in any state,
    // including one where a previous attempt already rewrote every object but
    // failed before committing (the server then still reports the old version).
    const remoteEntities = await fsRemote.walk();
    const entityByRaw = new Map(
      remoteEntities.map((entity) => [entity.keyRaw, entity])
    );
    const oldRaw: Array<{ raw: string; plain: string }> = [];
    const newRaw: Array<{ raw: string; plain: string }> = [];
    let unknownCount = 0;
    for (const entity of remoteEntities) {
      const raw = entity.keyRaw;
      if (!raw || raw.startsWith(".cloudsync")) continue;
      throwIfAborted();
      const plainOld = oldFs ? await tryDecryptName(oldFs, raw) : null;
      if (plainOld !== null) {
        oldRaw.push({ raw, plain: plainOld });
        continue;
      }
      const plainNew = await tryDecryptName(newFs, raw);
      if (plainNew !== null) {
        newRaw.push({ raw, plain: plainNew });
        continue;
      }
      unknownCount += 1;
    }

    // Never delete objects we cannot account for. In a mixed-generation vault
    // (e.g. a sync raced an earlier re-key) purging them would destroy files.
    // Abort instead so a full sync can reconcile first.
    if (unknownCount > 0) {
      await km.abortRotation(vaultId, deviceId).catch(() => {});
      throw new Error(
        "This vault contains objects from a different key generation. Run a normal sync first, then retry. Nothing was deleted."
      );
    }

    const files = oldRaw.length + newRaw.length;
    const total = oldRaw.length;
    let done = 0;
    const expectedRaw = new Set<string>(newRaw.map((entry) => entry.raw));
    const rewriteQueue = new PQueue({ concurrency: ROTATION_CONCURRENCY });
    await Promise.all(
      oldRaw.map(({ raw, plain }) =>
        rewriteQueue.add(async () => {
          throwIfAborted();
          let written: Entity;
          if (plain.endsWith("/")) {
            written = await newFs.mkdir(plain);
          } else {
            const entity = entityByRaw.get(raw);
            const mtime = entity?.mtimeCli ?? Date.now();
            const content = await readOldContent(plain, raw);
            written = await newFs.writeFile(plain, content, mtime, mtime);
          }
          const writtenRaw = written.keyEnc ?? written.keyRaw;
          if (writtenRaw) expectedRaw.add(writtenRaw);
          done += 1;
          onProgress?.(`Re-encrypting ${done}/${total}...`);
        })
      )
    );

    throwIfAborted();
    onProgress?.(`Verifying ${expectedRaw.size} item(s)...`);
    const verifyQueue = new PQueue({ concurrency: ROTATION_CONCURRENCY });
    await Promise.all(
      [...expectedRaw].map((raw) =>
        verifyQueue.add(async () => {
          throwIfAborted();
          await writeRemote.stat(raw);
        })
      )
    );

    throwIfAborted();
    if (oldRaw.length > 0) {
      onProgress?.("Removing old encrypted objects...");
      const batches: string[][] = [];
      for (let i = 0; i < oldRaw.length; i += PURGE_BATCH_SIZE) {
        batches.push(
          oldRaw.slice(i, i + PURGE_BATCH_SIZE).map((entry) => entry.raw)
        );
      }
      const purgeQueue = new PQueue({ concurrency: PURGE_CONCURRENCY });
      await Promise.all(
        batches.map((batch) =>
          purgeQueue.add(async () => {
            throwIfAborted();
            await fsRemote.purgeMany(batch);
          })
        )
      );
    }

    throwIfAborted();
    onProgress?.("Purging old history and trash...");
    await km.purgeVaultDerivatives(vaultId);

    throwIfAborted();
    onProgress?.("Re-sharing the new key with collaborators...");
    const owner = (cs.username || "").toLowerCase();
    const members = await km.listCollaborators(vaultId);
    for (const member of members) {
      if (member.toLowerCase() === owner) continue;
      await km.shareVaultKeyWith({
        vaultId,
        version: newVersion,
        recipientUsername: member,
        vk: newVk,
      });
    }

    throwIfAborted();
    onProgress?.("Committing...");
    await km.commitRotation(vaultId, newVersion, deviceId);
    await km.setOwnedVaultKey(vaultId, newVersion, newVk);
    plugin.clearCachedClients();
    return {
      keyVersion: newVersion,
      files,
      resumed: wasRotating || localVersion !== serverVersion,
    };
  } finally {
    fsRemote.setIntegrityKey(oldIntegrityKey);
    fsRemote.setRotationMode(false);
    writeRemote.setRotationMode(false);
    plugin.clearCachedClients();
  }
}
