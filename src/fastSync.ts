import type { Entity, RemotelySavePluginSettings } from "./baseTypes";
import { copyFile, copyFileOrFolder } from "./copyLogic";
import type { FakeFs } from "./fsAll";
import type { FakeFsEncrypt } from "./fsEncrypt";
import type { VaultChangeItem } from "./fsWorker";
import {
  clearPrevSyncRecordByVaultAndProfile,
  type InternalDBs,
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
  settings: RemotelySavePluginSettings
): Promise<boolean> {
  // Check if file exists locally
  let localStat: Entity | null = null;
  try {
    localStat = await fsLocal.stat(path);
  } catch {
    localStat = null;
  }

  if (localStat !== null) {
    // Local exists -> upload
    if (
      settings.skipSizeLargerThan &&
      settings.skipSizeLargerThan > 0 &&
      localStat.size &&
      localStat.size > settings.skipSizeLargerThan * 1024 * 1024
    ) {
      console.warn(`CloudSync: Skipping large file ${path} (${localStat.size} bytes)`);
      return false;
    }

    const { entity } = await copyFileOrFolder(path, fsLocal, fsEncrypt);
    fullfillMTimeOfRemoteEntityInplace(entity, localStat.mtimeCli!);
    await upsertPrevSyncRecordByVaultAndProfile(
      db,
      vaultRandomID,
      profileID,
      entity
    );
    return true;
  } else {
    // Local does not exist -> deleted locally -> remove remote
    try {
      await fsEncrypt.rm(path);
    } catch (err: any) {
      // Ignore not found on remote
      console.debug(`CloudSync rm on remote for ${path}:`, err);
    }
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
  profileID: string
): Promise<{ action: "pulled" | "deleted" | "skipped"; path: string }> {
  // Decrypt remote key
  const plainKey = await fsEncrypt.decryptRemoteKey(change.key);

  if (change.action === "put") {
    // Check if local exists
    let localStat: Entity | null = null;
    try {
      localStat = await fsLocal.stat(plainKey);
    } catch {
      localStat = null;
    }

    if (localStat !== null && localStat.mtimeCli !== undefined) {
      // If local mtime matches change.mtime within tolerance, we already have it
      if (isMTimeEqual(localStat.mtimeCli, change.mtime, 1500)) {
        return { action: "skipped", path: plainKey };
      }
      // If local file is strictly newer than change.mtime by more than tolerance, avoid overwriting
      if (localStat.mtimeCli > change.mtime + 1500) {
        console.warn(
          `CloudSync: Local file ${plainKey} is newer than remote change (${localStat.mtimeCli} > ${change.mtime}), skipping fast pull.`
        );
        return { action: "skipped", path: plainKey };
      }
    }

    // Pull file from remote to local
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
    return { action: "pulled", path: plainKey };
  } else if (change.action === "delete") {
    let localExists = false;
    try {
      await fsLocal.stat(plainKey);
      localExists = true;
    } catch {
      localExists = false;
    }

    if (localExists) {
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
