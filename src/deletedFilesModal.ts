import { App, Modal, Notice, requestUrl } from "obsidian";
import type CloudSyncPlugin from "./main";

interface TrashFile {
  key: string;
  displayPath: string;
  size: number;
  deletedAt: number;
}

export class DeletedFilesModal extends Modal {
  plugin: CloudSyncPlugin;
  bulkRestore: boolean;
  private files: TrashFile[] = [];
  private isLoading = true;

  constructor(app: App, plugin: CloudSyncPlugin, bulkRestore = false) {
    super(app);
    this.plugin = plugin;
    this.bulkRestore = bulkRestore;
  }

  async onOpen() {
    await this.fetchDeletedFiles();
    if (this.bulkRestore && this.files.length > 0) {
      await this.handleBulkRestore();
    } else {
      this.render();
    }
  }

  onClose() {
    this.contentEl.empty();
  }

  private async fetchDeletedFiles() {
    const cs = this.plugin.settings.cloudsync;
    const vault = cs.vaultId || this.app.vault.getName();
    const ownerQuery =
      cs.vaultOwner &&
      cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
        ? `&owner=${encodeURIComponent(cs.vaultOwner)}`
        : "";
    this.isLoading = true;

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/trash?vault=${encodeURIComponent(vault)}${ownerQuery}`,
        method: "GET",
        headers: {
          Authorization: `Bearer ${cs.token}`,
        },
        throw: false,
      });

      if (res.status === 200 && Array.isArray(res.json?.files)) {
        const rawFiles = res.json.files;
        const { fsEncrypt } = this.plugin.getOrCreateClients();
        const mapped: TrashFile[] = [];

        for (const f of rawFiles) {
          let displayPath = f.key;
          if (fsEncrypt && !fsEncrypt.isPasswordEmpty()) {
            try {
              displayPath = await fsEncrypt.decryptRemoteKey(f.key);
            } catch {
              displayPath = f.key;
            }
          }
          mapped.push({
            key: f.key,
            displayPath,
            size: f.size,
            deletedAt: f.deletedAt,
          });
        }
        this.files = mapped;
      } else {
        this.files = [];
      }
    } catch (err) {
      console.error("Failed to fetch deleted files:", err);
      this.files = [];
    } finally {
      this.isLoading = false;
    }
  }

  private async restoreFile(file: TrashFile) {
    const cs = this.plugin.settings.cloudsync;
    const vault = cs.vaultId || this.app.vault.getName();
    const ownerQuery =
      cs.vaultOwner &&
      cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
        ? `&owner=${encodeURIComponent(cs.vaultOwner)}`
        : "";

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/trash/restore?vault=${encodeURIComponent(vault)}${ownerQuery}`,
        method: "POST",
        headers: {
          Authorization: `Bearer ${cs.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ key: file.key }),
        throw: false,
      });

      if (res.status === 200) {
        new Notice(`Restored: ${file.displayPath}`);
        await this.fetchDeletedFiles();
        this.render();
        this.plugin.syncRun("manual");
      } else {
        new Notice(res.json?.error || "Failed to restore file.");
      }
    } catch (err: any) {
      new Notice(`Error restoring file: ${err?.message || err}`);
    }
  }

  private async handleBulkRestore() {
    if (
      !confirm(
        `Are you sure you want to restore all ${this.files.length} deleted files?`
      )
    ) {
      this.render();
      return;
    }

    const total = this.files.length;
    new Notice(`Restoring ${total} files...`);
    this.isLoading = true;
    this.render();

    const cs = this.plugin.settings.cloudsync;
    const vault = cs.vaultId || this.app.vault.getName();
    const ownerQuery =
      cs.vaultOwner &&
      cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
        ? `&owner=${encodeURIComponent(cs.vaultOwner)}`
        : "";
    let restoredCount = 0;

    for (const f of this.files) {
      try {
        const res = await requestUrl({
          url: `${cs.serverUrl}/api/sync/trash/restore?vault=${encodeURIComponent(vault)}${ownerQuery}`,
          method: "POST",
          headers: {
            Authorization: `Bearer ${cs.token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ key: f.key }),
          throw: false,
        });
        if (res.status === 200) {
          restoredCount++;
        }
      } catch (err) {
        console.error(`Failed to restore ${f.displayPath}:`, err);
      }
    }

    new Notice(`Restored ${restoredCount} of ${total} files.`);
    await this.plugin.syncRun("manual");
    this.close();
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", {
      text: "Deleted files",
      cls: "modal-title",
    });

    contentEl.createEl("p", {
      cls: "u-muted",
      text: "Files deleted from your vault are retained in cloud storage for 30 days.",
    });

    const listContainer = contentEl.createDiv({
      cls: "deleted-files-list",
    });

    if (this.isLoading) {
      listContainer.createEl("p", {
        cls: "u-muted",
        text: "Loading deleted files...",
      });
    } else if (this.files.length === 0) {
      listContainer.createEl("p", {
        cls: "u-muted",
        text: "No recently deleted files found.",
      });
    } else {
      for (const f of this.files) {
        const row = listContainer.createDiv({ cls: "share-user-row" });
        const textCol = row.createDiv();
        textCol.createDiv({ text: f.displayPath, cls: "share-username" });
        textCol.createDiv({
          text: `Deleted: ${new Date(f.deletedAt).toLocaleString()} • ${(
            f.size / 1024
          ).toFixed(1)} KB`,
          cls: "device-card-meta",
        });

        const restoreBtn = row.createEl("button", {
          cls: "mod-cta",
          text: "Restore",
        });
        restoreBtn.onclick = () => this.restoreFile(f);
      }
    }

    const footer = contentEl.createDiv({ cls: "modal-button-container" });
    if (this.files.length > 0) {
      const bulkBtn = footer.createEl("button", {
        text: `Bulk restore (${this.files.length})`,
      });
      bulkBtn.onclick = () => this.handleBulkRestore();
    }
    footer.createEl("button", { text: "Done" }, (btn) => {
      btn.onclick = () => this.close();
    });
  }
}
