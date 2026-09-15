import { App, Modal, Notice, requestUrl } from "obsidian";
import type CloudSyncPlugin from "./main";

interface VersionItem {
  versionId: string;
  timestamp: number;
  size: number;
}

interface DiffChunk {
  type: "added" | "removed" | "unchanged";
  text: string;
}

function computeLineDiff(oldText: string, newText: string): DiffChunk[] {
  const oldLines = oldText.split("\n");
  const newLines = newText.split("\n");

  // Trim common prefix and suffix
  let start = 0;
  while (
    start < oldLines.length &&
    start < newLines.length &&
    oldLines[start] === newLines[start]
  ) {
    start++;
  }

  let oldEnd = oldLines.length - 1;
  let newEnd = newLines.length - 1;
  while (
    oldEnd >= start &&
    newEnd >= start &&
    oldLines[oldEnd] === newLines[newEnd]
  ) {
    oldEnd--;
    newEnd--;
  }

  const prefixChunks: DiffChunk[] = oldLines
    .slice(0, start)
    .map((text) => ({ type: "unchanged", text }));

  const suffixChunks: DiffChunk[] = oldLines
    .slice(oldEnd + 1)
    .map((text) => ({ type: "unchanged", text }));

  const middleOld = oldLines.slice(start, oldEnd + 1);
  const middleNew = newLines.slice(start, newEnd + 1);

  const m = middleOld.length;
  const n = middleNew.length;

  if (m === 0 && n === 0) {
    return [...prefixChunks, ...suffixChunks];
  }

  if (m > 1500 || n > 1500) {
    return [
      ...prefixChunks,
      ...middleOld.map((text) => ({ type: "removed" as const, text })),
      ...middleNew.map((text) => ({ type: "added" as const, text })),
      ...suffixChunks,
    ];
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array(n + 1).fill(0)
  );

  for (let i = 0; i < m; i++) {
    for (let j = 0; j < n; j++) {
      if (middleOld[i] === middleNew[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const middleDiff: DiffChunk[] = [];
  let i = m;
  let j = n;

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && middleOld[i - 1] === middleNew[j - 1]) {
      middleDiff.unshift({ type: "unchanged", text: middleOld[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      middleDiff.unshift({ type: "added", text: middleNew[j - 1] });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      middleDiff.unshift({ type: "removed", text: middleOld[i - 1] });
      i--;
    }
  }

  return [...prefixChunks, ...middleDiff, ...suffixChunks];
}

export class VersionHistoryModal extends Modal {
  plugin: CloudSyncPlugin;
  filePath: string;
  private versions: VersionItem[] = [];
  private selectedVersionId: string | null = null;
  private selectedContent: string | null = null;
  private currentContent = "";
  private showDiff = true;
  private isLoading = true;
  private isRestoring = false;

  constructor(app: App, plugin: CloudSyncPlugin, filePath: string) {
    super(app);
    this.plugin = plugin;
    this.filePath = filePath;
  }

  async onOpen() {
    this.modalEl.addClass("history-modal", "mod-lg");
    await this.loadCurrentContent();
    await this.fetchVersions();
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private async loadCurrentContent() {
    try {
      const exists = await this.app.vault.adapter.exists(this.filePath);
      if (exists) {
        this.currentContent = await this.app.vault.adapter.read(this.filePath);
      } else {
        this.currentContent = "";
      }
    } catch {
      this.currentContent = "";
    }
  }

  private async getEncryptedKey(): Promise<string> {
    const { fsEncrypt } = this.plugin.getOrCreateClients();
    if (!fsEncrypt || fsEncrypt.isPasswordEmpty()) {
      return this.filePath;
    }
    try {
      return await (fsEncrypt as any)._encryptName(this.filePath);
    } catch {
      return this.filePath;
    }
  }

  private async fetchVersions() {
    this.isLoading = true;
    const cs = this.plugin.settings.cloudsync;
    const vault = cs.vaultId || this.app.vault.getName();
    const ownerQuery =
      cs.vaultOwner &&
      cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
        ? `&owner=${encodeURIComponent(cs.vaultOwner)}`
        : "";

    try {
      const encKey = await this.getEncryptedKey();
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/history?vault=${encodeURIComponent(vault)}${ownerQuery}&key=${encodeURIComponent(encKey)}`,
        method: "GET",
        headers: { Authorization: `Bearer ${cs.token}` },
        throw: false,
      });

      if (res.status === 200 && res.json?.versions) {
        this.versions = res.json.versions;
        if (this.versions.length > 0) {
          this.selectedVersionId = this.versions[0].versionId;
          await this.loadVersionContent(this.versions[0].versionId);
        }
      } else {
        this.versions = [];
      }
    } catch (err) {
      console.error("Failed to fetch version history:", err);
      this.versions = [];
    } finally {
      this.isLoading = false;
    }
  }

  private async loadVersionContent(versionId: string) {
    const cs = this.plugin.settings.cloudsync;
    const vault = cs.vaultId || this.app.vault.getName();
    const ownerQuery =
      cs.vaultOwner &&
      cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
        ? `&owner=${encodeURIComponent(cs.vaultOwner)}`
        : "";
    const encKey = await this.getEncryptedKey();

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/history/version?vault=${encodeURIComponent(vault)}${ownerQuery}&key=${encodeURIComponent(encKey)}&versionId=${encodeURIComponent(versionId)}`,
        method: "GET",
        headers: { Authorization: `Bearer ${cs.token}` },
        throw: false,
      });

      if (res.status === 200) {
        const { fsEncrypt } = this.plugin.getOrCreateClients();
        if (fsEncrypt && !fsEncrypt.isPasswordEmpty()) {
          const decrypted = await (fsEncrypt as any)._decryptContent(res.arrayBuffer);
          this.selectedContent = new TextDecoder().decode(decrypted);
        } else {
          this.selectedContent = res.text;
        }
      } else {
        this.selectedContent = "[Unable to load version content]";
      }
    } catch (err: any) {
      this.selectedContent = `[Error decrypting version: ${err?.message || err}]`;
    }
  }

  private async restoreSelectedVersion() {
    if (!this.selectedVersionId || this.selectedContent === null) return;

    if (
      !confirm(
        `Restore this version of "${this.filePath}"?\n\nThis will replace the current file contents with this historical snapshot.`
      )
    ) {
      return;
    }

    this.isRestoring = true;
    this.render();

    try {
      await this.app.vault.adapter.write(this.filePath, this.selectedContent);
      new Notice(`Restored "${this.filePath}".`);
      this.plugin.syncRun("manual");
      this.close();
    } catch (err: any) {
      new Notice(`Failed to restore version: ${err?.message || err}`);
      this.isRestoring = false;
      this.render();
    }
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();

    const header = contentEl.createDiv({ cls: "sync-modal-header" });
    header.createEl("h2", {
      text: `Version history for "${this.filePath.split("/").pop()}"`,
      cls: "modal-title",
    });
    header.createEl("p", {
      text: this.filePath,
      cls: "u-muted",
    });

    if (this.isLoading) {
      contentEl.createEl("p", {
        text: "Retrieving version history from cloud...",
        cls: "u-muted",
      });
      return;
    }

    if (this.versions.length === 0) {
      contentEl.createEl("p", {
        text: "No version history found for this file. Versions are recorded whenever files are synced to the remote vault.",
        cls: "u-muted",
      });
      const btnRow = contentEl.createDiv({ cls: "modal-button-container" });
      btnRow.createEl("button", { text: "Done" }, (btn) => {
        btn.onclick = () => this.close();
      });
      return;
    }

    const layout = contentEl.createDiv({ cls: "history-layout" });

    const sidebar = layout.createDiv({ cls: "history-sidebar" });
    for (const v of this.versions) {
      const itemEl = sidebar.createDiv({
        cls: `history-item ${v.versionId === this.selectedVersionId ? "is-selected" : ""}`,
      });

      const date = new Date(v.timestamp);
      itemEl.createSpan({
        text: date.toLocaleString(),
        cls: "history-item-time",
      });

      const kb = (v.size / 1024).toFixed(1);
      itemEl.createSpan({
        text: `${kb} KB`,
        cls: "history-item-meta",
      });

      itemEl.onclick = async () => {
        if (this.selectedVersionId === v.versionId) return;
        this.selectedVersionId = v.versionId;
        await this.loadVersionContent(v.versionId);
        this.render();
      };
    }

    const mainPane = layout.createDiv({ cls: "history-main" });

    const actionBar = mainPane.createDiv({ cls: "history-actions" });

    const toggleDiffBtn = actionBar.createEl("button", {
      text: this.showDiff ? "Show raw content" : "Show changes",
    });
    toggleDiffBtn.onclick = () => {
      this.showDiff = !this.showDiff;
      this.render();
    };

    const copyBtn = actionBar.createEl("button", {
      text: "Copy to clipboard",
    });
    copyBtn.onclick = async () => {
      if (this.selectedContent) {
        await navigator.clipboard.writeText(this.selectedContent);
        new Notice("Copied version content to clipboard.");
      }
    };

    const restoreBtn = actionBar.createEl("button", {
      text: this.isRestoring ? "Restoring..." : "Restore this version",
      cls: "mod-cta",
    });
    restoreBtn.disabled = this.isRestoring || !this.selectedContent;
    restoreBtn.onclick = async () => {
      await this.restoreSelectedVersion();
    };

    const viewer = mainPane.createDiv({
      cls: "history-diff-container",
    });

    if (!this.selectedContent) {
      viewer.createEl("p", { text: "Loading version content...", cls: "u-muted" });
    } else if (!this.showDiff) {
      viewer.createEl("pre", {
        cls: "history-raw-preview",
        text: this.selectedContent,
      });
    } else {
      const diffs = computeLineDiff(this.selectedContent, this.currentContent);
      for (const d of diffs) {
        const lineEl = viewer.createDiv({
          cls: `diff-line diff-${d.type}`,
        });
        const prefix = d.type === "added" ? "+ " : d.type === "removed" ? "- " : "  ";
        lineEl.setText(`${prefix}${d.text}`);
      }
    }
  }
}
