import {
  DEFAULT_DEBUG_FOLDER,
  DEFAULT_DEVICE_CONFIGS_FOLDER,
  type Entity,
  type RemotelySavePluginSettings,
} from "./baseTypes";
import { copyFile, copyFileOrFolder } from "./copyLogic";
import type { FakeFs } from "./fsAll";
import type { FakeFsEncrypt } from "./fsEncrypt";
import type { VaultChangeItem } from "./fsWorker";
import {
  type InternalDBs,
  clearPrevSyncRecordByVaultAndProfile,
  getPrevSyncRecordByVaultAndProfile,
  upsertPrevSyncRecordByVaultAndProfile,
} from "./localdb";
import { fullfillMTimeOfRemoteEntityInplace, isMTimeEqual } from "./sync";

export interface FastSyncResult {
  pushedCount: number;
  pulledCount: number;
  deletedCount: number;
  errors: Array<{ path: string; error: any }>;
}

export async function fastPushPath(
  path: string,
  fsLocal: FakeFs,
  fsEncrypt: FakeFsEncrypt,
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string,
  settings: RemotelySavePluginSettings,
  cursor?: { line: number; ch: number },
  configDir?: string,
  isDeletion = false
): Promise<boolean> {
  const isNotesOnly = (settings.settingsSyncMode ?? "notes_only") !== "shared";
  const cfgDir = configDir || ".obsidian";
  if (
    path.startsWith(DEFAULT_DEBUG_FOLDER) ||
    path.startsWith(DEFAULT_DEVICE_CONFIGS_FOLDER) ||
    (isNotesOnly &&
      (path.startsWith(".obsidian/") ||
        path.startsWith(`${cfgDir}/`) ||
        path === ".obsidian" ||
        path === cfgDir))
  ) {
    return false;
  }

  let localStat: Entity | null = null;
  try {
    localStat = await fsLocal.stat(path);
  } catch {
    localStat = null;
  }

  if (localStat !== null) {
    if (
      settings.skipSizeLargerThan &&
      settings.skipSizeLargerThan > 0 &&
      localStat.size &&
      localStat.size > settings.skipSizeLargerThan * 1024 * 1024
    ) {
      return false;
    }

    let entity: Entity;
    if (path.endsWith("/")) {
      const res = await copyFileOrFolder(path, fsLocal, fsEncrypt);
      entity = res.entity;
    } else {
      const content = await fsLocal.readFile(path);
      entity = await fsEncrypt.writeFile(
        path,
        content,
        localStat.mtimeCli!,
        localStat.ctimeCli ?? localStat.mtimeCli!,
        cursor
      );
    }

    fullfillMTimeOfRemoteEntityInplace(entity, localStat.mtimeCli!);
    await upsertPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      entity
    );
    return true;
  } else {
    // The local file is gone. Only delete the remote copy when the vault
    // explicitly reported a deletion AND we have a previous sync record for it.
    // A transient stat/read failure must never be interpreted as a deletion.
    const prevSyncRecord = await getPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      path
    );
    if (
      !isDeletion ||
      prevSyncRecord === null ||
      prevSyncRecord === undefined
    ) {
      return false;
    }
    try {
      await fsEncrypt.rm(path);
    } catch {}
    await clearPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      path
    );
    return true;
  }
}

export async function fastPullChange(
  change: VaultChangeItem,
  fsLocal: FakeFs,
  fsEncrypt: FakeFsEncrypt,
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string,
  settings?: RemotelySavePluginSettings,
  configDir?: string
): Promise<{
  action: "pulled" | "deleted" | "cursor" | "skipped";
  path: string;
  cursor?: { line: number; ch: number };
  deviceId?: string;
  deviceName?: string;
}> {
  const plainKey = await fsEncrypt.decryptRemoteKey(change.key);

  // A name that does not decrypt to a plausible path belongs to another key
  // generation; never let it create or delete local files.
  if (
    plainKey.length === 0 ||
    plainKey.includes("\uFFFD") ||
    plainKey.includes("\u0000")
  ) {
    return { action: "skipped", path: plainKey };
  }

  if (
    plainKey.startsWith(DEFAULT_DEBUG_FOLDER) ||
    plainKey.startsWith(DEFAULT_DEVICE_CONFIGS_FOLDER)
  ) {
    return {
      action: "skipped",
      path: plainKey,
      cursor: change.cursor,
      deviceId: change.deviceId,
      deviceName: change.deviceName,
    };
  }

  const isNotesOnly = (settings?.settingsSyncMode ?? "notes_only") !== "shared";
  const cfgDir = configDir || ".obsidian";
  if (
    isNotesOnly &&
    (plainKey.startsWith(".obsidian/") ||
      plainKey.startsWith(`${cfgDir}/`) ||
      plainKey === ".obsidian" ||
      plainKey === cfgDir)
  ) {
    return {
      action: "skipped",
      path: plainKey,
      cursor: change.cursor,
      deviceId: change.deviceId,
      deviceName: change.deviceName,
    };
  }

  if (change.action === "cursor") {
    return {
      action: "cursor",
      path: plainKey,
      cursor: change.cursor,
      deviceId: change.deviceId,
      deviceName: change.deviceName,
    };
  }

  if (change.action === "put") {
    let localStat: Entity | null = null;
    try {
      localStat = await fsLocal.stat(plainKey);
    } catch {
      localStat = null;
    }

    if (localStat !== null && localStat.mtimeCli !== undefined) {
      if (isMTimeEqual(localStat.mtimeCli, change.mtime, 1500)) {
        return {
          action: "skipped",
          path: plainKey,
          cursor: change.cursor,
          deviceId: change.deviceId,
          deviceName: change.deviceName,
        };
      }
      if (localStat.mtimeCli > change.mtime + 1500) {
        return {
          action: "skipped",
          path: plainKey,
          cursor: change.cursor,
          deviceId: change.deviceId,
          deviceName: change.deviceName,
        };
      }
    }

    let entity: Entity;
    if (plainKey.endsWith("/")) {
      entity = await fsLocal.mkdir(plainKey);
    } else {
      const res = await copyFile(plainKey, fsEncrypt, fsLocal);
      entity = res.entity;
    }

    await upsertPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      entity
    );
    return {
      action: "pulled",
      path: plainKey,
      cursor: change.cursor,
      deviceId: change.deviceId,
      deviceName: change.deviceName,
    };
  } else if (change.action === "delete") {
    // Only mirror a remote deletion when this path was previously synced by
    // this profile. A stale-generation or garbage name must never be able to
    // delete an unrelated local file.
    const prevSyncRecord = await getPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      plainKey
    );
    if (prevSyncRecord === null || prevSyncRecord === undefined) {
      return { action: "skipped", path: plainKey };
    }

    let localStat: Entity | null = null;
    try {
      localStat = await fsLocal.stat(plainKey);
    } catch {
      localStat = null;
    }

    if (
      localStat !== null &&
      localStat.mtimeCli !== undefined &&
      !isMTimeEqual(localStat.mtimeCli, change.mtime, 1500)
    ) {
      if (localStat.mtimeCli > change.mtime + 1500) {
        // Local copy was modified after the remote deletion; keep it and let the
        // next full sync push it back instead of silently discarding the edit.
        return { action: "skipped", path: plainKey };
      }
    }

    if (localStat !== null) {
      await fsLocal.rm(plainKey);
    }
    await clearPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      plainKey
    );
    return { action: "deleted", path: plainKey };
  }

  return { action: "skipped", path: plainKey };
}
