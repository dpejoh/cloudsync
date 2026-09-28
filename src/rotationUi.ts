import { Notice } from "obsidian";
import type CloudSyncPlugin from "./main";
import { logRotation } from "./rotationLog";
import { rotateVaultKey } from "./vaultRotation";

export function confirmVaultRekey(): boolean {
  return confirm(
    "Re-key this vault?\n\n" +
      "A new vault key is generated and every file is re-encrypted. Old cloud trash and version history (encrypted with the previous key) are permanently removed. " +
      "Syncing pauses on all devices until it finishes, and collaborators receive the new key automatically."
  );
}

/** Runs a re-key with progress notifications. Returns true when it completed. */
export async function runVaultRekey(
  plugin: CloudSyncPlugin,
  vaultId: string
): Promise<boolean> {
  const notice = new Notice("Re-keying vault...", 0);
  let lastPersist = 0;
  const persistProgress = (message: string) => {
    const now = Date.now();
    if (now - lastPersist < 1000) return;
    lastPersist = now;
    plugin.settings.cloudsync.lastRotationProgress = {
      message,
      updatedAt: now,
    };
    plugin.saveSettings().catch(() => {});
  };

  const onProgress = (message: string) => {
    try {
      notice.setMessage(message);
    } catch {}
    plugin.statusBarElement?.setText(message);
    logRotation(plugin, message);
    persistProgress(message);
  };

  try {
    const result = await rotateVaultKey(plugin, vaultId, onProgress);
    notice.hide();
    plugin.settings.cloudsync.lastRotationProgress = undefined;
    plugin.settings.cloudsync.lastRotationError = undefined;
    await plugin.saveSettings();
    plugin.statusBarElement?.setText("Synced");
    logRotation(
      plugin,
      `done: version ${result.keyVersion}, ${result.files} items`
    );
    new Notice(
      `Vault re-keyed (version ${result.keyVersion}, ${result.files} items).`
    );
    return true;
  } catch (err: any) {
    notice.hide();
    const message = `${err?.message || err}`;
    plugin.settings.cloudsync.lastRotationError = message;
    plugin.settings.cloudsync.lastRotationProgress = undefined;
    await plugin.saveSettings();
    plugin.statusBarElement?.setText("Re-key failed");
    logRotation(plugin, `failed: ${message}`);
    new Notice(
      `Re-key did not finish: ${message}. Open Settings -> Connected vault to retry.`,
      15000
    );
    return false;
  }
}
