import { type App, Notice, Platform } from "obsidian";
import {
  DEFAULT_DEVICE_CONFIGS_FOLDER,
  type Entity,
  type RemotelySavePluginSettings,
} from "./baseTypes";
import type { FakeFsEncrypt } from "./fsEncrypt";
import type { DeviceInfo, FakeFsWorker } from "./fsWorker";

export function initDeviceIdentity(settings: RemotelySavePluginSettings) {
  if (!settings.deviceId) {
    settings.deviceId = `dev_${Math.random().toString(36).substring(2, 10)}`;
  }

  if (!settings.deviceName) {
    if (Platform.isAndroidApp) {
      settings.deviceName = "Android Phone";
    } else if (Platform.isIosApp) {
      settings.deviceName = "iPhone / iPad";
    } else if (Platform.isLinux) {
      settings.deviceName = "Linux Desktop";
    } else if (Platform.isMacOS) {
      settings.deviceName = "Mac Desktop";
    } else if (Platform.isWin) {
      settings.deviceName = "Windows PC";
    } else {
      settings.deviceName = Platform.isMobile ? "Mobile Device" : "Desktop PC";
    }
  }

  if (!settings.settingsSyncMode) {
    settings.settingsSyncMode = "notes_only";
  }
}

async function getFilesToBackupInConfigDir(
  app: App
): Promise<Array<{ path: string; relPath: string; mtime: number }>> {
  const configDir = app.vault.configDir;
  const results: Array<{ path: string; relPath: string; mtime: number }> = [];
  const queue: string[] = [configDir];

  while (queue.length > 0) {
    const current = queue.shift()!;
    let listed: { files: string[]; folders: string[] };
    try {
      listed = await app.vault.adapter.list(current);
    } catch {
      continue;
    }

    for (const folder of listed.folders) {
      const name = folder.split("/").pop() || "";
      if (name === "cache" || name === ".trash" || name === ".git") continue;
      queue.push(folder);
    }

    for (const file of listed.files) {
      const fileName = file.split("/").pop() || "";
      const relPath = file.slice(configDir.length + 1);

      if (fileName.startsWith("workspace") || fileName === "graph.json" || fileName.startsWith(".")) {
        continue;
      }
      if (relPath.includes("cloudsync/data.json") || relPath.includes("remotely-save/data.json")) {
        continue;
      }

      try {
        const stat = await app.vault.adapter.stat(file);
        if (stat && stat.type === "file") {
          results.push({
            path: file,
            relPath,
            mtime: stat.mtime || Date.now(),
          });
        }
      } catch {}
    }
  }

  return results;
}

export async function backupDeviceSettings(
  app: App,
  fsEncrypt: FakeFsEncrypt,
  fsRemote: FakeFsWorker,
  settings: RemotelySavePluginSettings,
  onProgress?: (msg: string) => void
): Promise<{ fileCount: number; timestamp: number }> {
  initDeviceIdentity(settings);

  const deviceId = settings.deviceId!;
  const deviceName = settings.deviceName!;
  const files = await getFilesToBackupInConfigDir(app);

  onProgress?.(`Found ${files.length} configuration files to backup...`);

  let count = 0;
  for (const f of files) {
    count++;
    onProgress?.(`Backing up (${count}/${files.length}): ${f.relPath}`);

    const buffer = await app.vault.adapter.readBinary(f.path);
    const targetKey = `${DEFAULT_DEVICE_CONFIGS_FOLDER}${deviceId}/${f.relPath}`;

    await fsEncrypt.writeFile(targetKey, buffer, f.mtime, f.mtime);
  }

  const now = Date.now();
  const manifest = {
    deviceId,
    deviceName,
    platform: Platform.isMobile ? "mobile" : "desktop",
    backupTime: now,
    fileCount: files.length,
  };
  const manifestBuffer = new TextEncoder().encode(JSON.stringify(manifest, null, 2)).buffer;
  await fsEncrypt.writeFile(
    `${DEFAULT_DEVICE_CONFIGS_FOLDER}${deviceId}/_manifest.json`,
    manifestBuffer,
    now,
    now
  );

  await fsRemote.registerDevice({
    deviceId,
    deviceName,
    platform: Platform.isMobile ? "mobile" : "desktop",
    lastBackup: now,
    fileCount: files.length,
  });

  settings.lastSettingsBackupTime = now;
  return { fileCount: files.length, timestamp: now };
}

export async function restoreDeviceSettings(
  app: App,
  fsEncrypt: FakeFsEncrypt,
  sourceDeviceId: string,
  onProgress?: (msg: string) => void
): Promise<{ restoredCount: number }> {
  const configDir = app.vault.configDir;
  const prefix = `${DEFAULT_DEVICE_CONFIGS_FOLDER}${sourceDeviceId}/`;

  onProgress?.("Scanning remote device backup files...");
  const allFiles = await fsEncrypt.walk();
  const targetFiles = allFiles.filter(
    (e): e is Entity & { key: string } =>
      typeof e.key === "string" &&
      e.key.startsWith(prefix) &&
      !e.key.endsWith("/")
  );

  if (targetFiles.length === 0) {
    throw new Error(`No backup files found for device ID: ${sourceDeviceId}`);
  }

  let restored = 0;
  for (const e of targetFiles) {
    const relPath = e.key.slice(prefix.length);
    if (relPath === "_manifest.json") continue;
    if (
      relPath.includes("cloudsync/data.json") ||
      relPath.includes("remotely-save/data.json")
    ) {
      continue;
    }

    restored++;
    onProgress?.(`Restoring (${restored}/${targetFiles.length}): ${relPath}`);

    const content = await fsEncrypt.readFile(e.key);
    const destPath = `${configDir}/${relPath}`;

    const parts = destPath.split("/");
    parts.pop();
    const parentFolder = parts.join("/");
    if (parentFolder && !(await app.vault.adapter.exists(parentFolder))) {
      await app.vault.adapter.mkdir(parentFolder);
    }

    await app.vault.adapter.writeBinary(destPath, content);
  }

  return { restoredCount: restored };
}

export async function fetchRemoteDevices(
  fsRemote: FakeFsWorker
): Promise<DeviceInfo[]> {
  return await fsRemote.getDevices();
}
