import type CloudSyncPlugin from "./main";

/**
 * Appends re-key diagnostics to a local log file inside the plugin folder.
 * Used to watch long rotations in real time (tail -f rotation-debug.log).
 * Never throws: logging must not break a rotation.
 */
export function logRotation(plugin: CloudSyncPlugin, message: string): void {
  try {
    const line = `${new Date().toISOString()} ${message}\n`;
    console.log(`[CloudSync rotation] ${message}`);
    if (!plugin.settings?.debugRotationLog) return;
    const adapter = plugin.app?.vault?.adapter;
    if (!adapter) return;
    const path = `${plugin.app.vault.configDir}/plugins/${plugin.manifest.id}/rotation-debug.log`;
    adapter.append(path, line).catch(() => {});
  } catch {}
}
