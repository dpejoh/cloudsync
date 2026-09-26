import type { Extension } from "@codemirror/state";
import { type EditorView } from "@codemirror/view";
import { MarkdownView } from "obsidian";
import {
  createCursorListener,
  getDeviceColor,
  type RemoteCursorPresence,
  remoteCursorField,
  setRemotePresencesEffect,
} from "./editorPresence";
import type RemotelySavePlugin from "./main";

export class PresenceManager {
  private plugin: RemotelySavePlugin;
  private presences = new Map<string, RemoteCursorPresence>();
  private announcedPresences = new Set<string>();
  private localDebounceTimer: number | null = null;
  private cleanupInterval: number | null = null;
  private entranceTimers = new Set<number>();
  private isDestroyed = false;
  private lastSentCursor: { path: string; line: number; ch: number } | null =
    null;

  constructor(plugin: RemotelySavePlugin) {
    this.plugin = plugin;
    this.cleanupInterval = window.setInterval(() => {
      this.purgeStalePresences();
    }, 5000);
  }

  destroy(): void {
    this.sendLeaveSignal();
    this.isDestroyed = true;
    if (this.cleanupInterval !== null) {
      window.clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    if (this.localDebounceTimer !== null) {
      window.clearTimeout(this.localDebounceTimer);
      this.localDebounceTimer = null;
    }
    for (const timer of this.entranceTimers) {
      window.clearTimeout(timer);
    }
    this.entranceTimers.clear();
    this.presences.clear();
    this.announcedPresences.clear();
  }

  getEditorExtensions(): Extension[] {
    return [
      remoteCursorField,
      createCursorListener((cursor) => {
        const view =
          this.plugin.app.workspace.getActiveViewOfType(MarkdownView);
        if (view?.file?.path) {
          this.handleLocalCursor(view.file.path, cursor);
        }
      }),
    ];
  }

  updateRemotePresence(
    deviceId: string | undefined,
    deviceName: string | undefined,
    path: string,
    cursor: { line: number; ch: number }
  ): void {
    const normPath = path.replace(/^\/+/, "");
    const effectiveDeviceId =
      deviceId || `remote_${deviceName || "device"}`;
    const ownDeviceId = this.plugin.settings.deviceId;
    if (ownDeviceId && effectiveDeviceId === ownDeviceId) return;

    const friendlyName = deviceName || "Remote Device";
    const color = getDeviceColor(effectiveDeviceId);

    const announceKey = `${effectiveDeviceId}:${normPath}`;
    const isNew = !this.announcedPresences.has(announceKey);
    let firstSeenAt = Date.now();

    const existing = this.presences.get(effectiveDeviceId);
    if (existing && !isNew) {
      firstSeenAt = existing.firstSeenAt;
    } else if (isNew) {
      this.announcedPresences.add(announceKey);
      firstSeenAt = Date.now();
      const timer = window.setTimeout(() => {
        this.entranceTimers.delete(timer);
        this.dispatchPresencesToOpenLeaves();
      }, 3200);
      this.entranceTimers.add(timer);
    }

    this.presences.set(effectiveDeviceId, {
      deviceId: effectiveDeviceId,
      deviceName: friendlyName,
      color,
      path: normPath,
      line: cursor.line,
      ch: cursor.ch,
      updatedAt: Date.now(),
      firstSeenAt,
    });

    this.dispatchPresencesToOpenLeaves();
  }

  dispatchPresencesToOpenLeaves(): void {
    if (this.isDestroyed) return;
    const now = Date.now();
    this.plugin.app.workspace.iterateAllLeaves((leaf) => {
      if (leaf.view instanceof MarkdownView && leaf.view.file) {
        const leafPath = leaf.view.file.path.replace(/^\/+/, "");
        const matching = Array.from(this.presences.values()).filter((p) => {
          const pPath = p.path.replace(/^\/+/, "");
          return pPath === leafPath && now - p.updatedAt < 30000;
        });

        const editorWithCm = leaf.view.editor as unknown as { cm?: EditorView };
        const cm = editorWithCm?.cm;
        if (cm) {
          cm.dispatch({
            effects: setRemotePresencesEffect.of(matching),
          });
        }
      }
    });
  }

  removeRemotePresence(deviceId: string): void {
    const existing = this.presences.get(deviceId);
    if (existing) {
      this.presences.delete(deviceId);
      this.announcedPresences.delete(`${deviceId}:${existing.path}`);
      this.dispatchPresencesToOpenLeaves();
    }
  }

  handleLocalLeave(): void {
    if (this.lastSentCursor) {
      this.lastSentCursor = null;
      this.sendLeaveSignal();
    }
  }

  sendLeaveSignal(): void {
    const cs = this.plugin.settings.cloudsync;
    const deviceId = this.plugin.settings.deviceId;
    if (!cs?.token || !cs?.vaultId || !cs?.serverUrl || !deviceId) return;

    const url = `${cs.serverUrl.replace(/\/+$/, "")}/api/sync/cursor?vault=${encodeURIComponent(cs.vaultId)}`;
    try {
      if (typeof fetch !== "undefined") {
        fetch(url, {
          method: "DELETE",
          keepalive: true,
          headers: {
            Authorization: `Bearer ${cs.token}`,
            "x-device-id": deviceId,
          },
        }).catch(() => {});
      }
    } catch {}
  }

  handleLocalCursor(path: string, cursor: { line: number; ch: number }): void {
    if (this.plugin.isSyncing) return;
    const normPath = path.replace(/^\/+/, "");
    if (
      this.lastSentCursor &&
      this.lastSentCursor.path === normPath &&
      this.lastSentCursor.line === cursor.line &&
      this.lastSentCursor.ch === cursor.ch
    ) {
      return;
    }

    this.plugin.lastLocalCursor = { path: normPath, line: cursor.line, ch: cursor.ch };

    if (this.localDebounceTimer !== null) {
      window.clearTimeout(this.localDebounceTimer);
    }

    this.localDebounceTimer = window.setTimeout(async () => {
      this.lastSentCursor = { path: normPath, line: cursor.line, ch: cursor.ch };
      await this.plugin.sendCursorUpdate(normPath, cursor);
    }, 300);
  }

  private purgeStalePresences(): void {
    const now = Date.now();
    let changed = false;
    for (const [id, item] of this.presences.entries()) {
      if (now - item.updatedAt > 30000) {
        this.presences.delete(id);
        this.announcedPresences.delete(`${id}:${item.path}`);
        changed = true;
      }
    }
    if (changed) {
      this.dispatchPresencesToOpenLeaves();
    }
  }
}
