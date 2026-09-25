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
  settings: RemotelySavePluginSettings,
  cursor?: { line: number; ch: number },
  configDir?: string
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
}> {
  const plainKey = await fsEncrypt.decryptRemoteKey(change.key);

  if (
    plainKey.startsWith(DEFAULT_DEBUG_FOLDER) ||
    plainKey.startsWith(DEFAULT_DEVICE_CONFIGS_FOLDER)
  ) {
    return { action: "skipped", path: plainKey, cursor: change.cursor };
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
    return { action: "skipped", path: plainKey, cursor: change.cursor };
  }

  if (change.action === "cursor") {
    return { action: "cursor", path: plainKey, cursor: change.cursor };
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
        return { action: "skipped", path: plainKey, cursor: change.cursor };
      }
      if (localStat.mtimeCli > change.mtime + 1500) {
        return { action: "skipped", path: plainKey, cursor: change.cursor };
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
    return { action: "pulled", path: plainKey, cursor: change.cursor };
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
