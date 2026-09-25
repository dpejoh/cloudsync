import { App, Modal, Notice, Setting, requestUrl } from "obsidian";
import type CloudSyncPlugin from "./main";

interface RemoteVaultItem {
  name: string;
  revision?: number;
  isShared?: boolean;
  owner?: string;
  ownerId?: string;
}

export class VaultPickerModal extends Modal {
  plugin: CloudSyncPlugin;
  private vaults: RemoteVaultItem[] = [];
  private isLoading = true;
  private newVaultName = "";
  private onVaultChanged?: (vaultName: string) => void;

  constructor(
    app: App,
    plugin: CloudSyncPlugin,
    onVaultChanged?: (vaultName: string) => void
  ) {
    super(app);
    this.plugin = plugin;
    this.onVaultChanged = onVaultChanged;
  }

  async onOpen() {
    this.contentEl.addClass("vault-picker-modal");
    const localName = this.app.vault.getName().trim();
    if (this.isValidName(localName)) {
      this.newVaultName = localName;
    }
    await this.fetchVaults();
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private async fetchVaults() {
    const cs = this.plugin.settings.cloudsync;
    if (!cs.serverUrl || !cs.token) return;

    this.isLoading = true;
    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/vaults`,
        method: "GET",
        headers: {
          Authorization: `Bearer ${cs.token}`,
        },
        throw: false,
      });

      if (res.status === 200 && Array.isArray(res.json?.vaults)) {
        this.vaults = res.json.vaults;
      } else {
        this.vaults = [];
      }
    } catch (err) {
      console.error("Failed to fetch remote vaults:", err);
      this.vaults = [];
    } finally {
      this.isLoading = false;
    }
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();

    const cs = this.plugin.settings.cloudsync;
    const currentVaultId = cs.vaultId || "";

    contentEl.createEl("h2", { text: "Choose a remote vault" });
    contentEl.createEl("p", {
      text: "Connect this local vault to an existing cloud vault, or create a brand new remote vault container.",
      cls: "setting-item-description",
    });

    contentEl.createEl("h3", { text: "Create new remote vault" });

    let createBtn: any = null;
    new Setting(contentEl)
      .setName("Remote vault name")
      .setDesc("Alphanumeric characters, hyphens, and underscores only.")
      .addText((text) => {
        text
          .setPlaceholder("e.g. Work, Notes, Research")
          .setValue(this.newVaultName)
          .onChange((val) => {
            this.newVaultName = val.trim();
            if (createBtn) {
              createBtn.setDisabled(!this.isValidName(this.newVaultName));
            }
          });
      })
      .addButton((btn) => {
        createBtn = btn;
        btn
          .setButtonText("Create & Connect")
          .setCta()
          .setDisabled(!this.isValidName(this.newVaultName))
          .onClick(async () => {
            await this.handleCreateVault(this.newVaultName);
          });
      });

    contentEl.createEl("h3", { text: "Available remote vaults" });

    if (this.isLoading) {
      const loadingEl = contentEl.createDiv({ cls: "loading-notice" });
      loadingEl.setText("Fetching remote vaults from cloud...");
      return;
    }

    if (this.vaults.length === 0) {
      const emptyEl = contentEl.createDiv({ cls: "empty-notice" });
      emptyEl.setText(
        "No remote vaults found on your account. Create one above to get started."
      );
      return;
    }

    const listContainer = contentEl.createDiv({
      cls: "vault-list",
    });

    for (const v of this.vaults) {
      const isCurrentOwner = v.isShared
        ? cs.vaultOwner?.toLowerCase() === (v.owner || "").toLowerCase()
        : !cs.vaultOwner ||
          cs.vaultOwner.toLowerCase() === (cs.username || "").toLowerCase();
      const isConnected = currentVaultId === v.name && isCurrentOwner;
      const setting = new Setting(listContainer);

      const nameFrag = createFragment((f) => {
        f.createSpan({ text: v.name, cls: "vault-name" });
        if (v.isShared) {
          f.createSpan({
            text: ` (Shared by ${v.owner})`,
            cls: "badge-shared",
          });
        }
        if (isConnected) {
          f.createSpan({
            text: " Connected",
            cls: "badge-connected",
          });
        }
      });

      setting.setName(nameFrag);
      setting.setDesc(
        isConnected
          ? "This local device is currently syncing with this remote vault."
          : v.isShared
          ? `Shared with you by ${v.owner}.`
          : v.revision
          ? `Revision: ${v.revision}`
          : "Available in your cloud account"
      );

      if (isConnected) {
        setting.addButton((btn) => {
          btn
            .setButtonText("Disconnect")
            .setClass("mod-destructive")
            .onClick(async () => {
              if (
                !confirm(
                  `Disconnect from "${v.name}"?\n\nYour local files will not be deleted, but syncing will stop until you connect a vault again.`
                )
              ) {
                return;
              }

              cs.vaultId = "";
              cs.vaultOwner = "";
              this.plugin.clearCachedClients();
              await this.plugin.saveSettings();
              new Notice(`Disconnected from remote vault "${v.name}".`);
              this.onVaultChanged?.("");
              this.render();
            });
        });
      } else {
        setting.addButton((btn) => {
          btn
            .setButtonText("Connect")
            .setCta()
            .onClick(async () => {
              await this.handleConnectVault(
                v.name,
                v.isShared ? v.owner : undefined
              );
            });
        });

        if (!v.isShared) {
          setting.addExtraButton((btn) => {
            btn
              .setIcon("lucide-trash-2")
              .setTooltip(`Delete remote vault "${v.name}" from cloud`)
              .onClick(async () => {
                if (
                  !confirm(
                    `Are you sure you want to delete the remote vault "${v.name}" from the cloud?\n\nWARNING: All remote files, versions, and trash for this vault will be permanently deleted! Your local notes will remain untouched.`
                  )
                ) {
                  return;
                }

                await this.handleDeleteVault(v.name);
              });
          });
        }
      }
    }
  }

  private isValidName(name: string): boolean {
    return /^[a-zA-Z0-9._-]{1,64}$/.test(name);
  }

  private async handleCreateVault(name: string) {
    const cs = this.plugin.settings.cloudsync;
    if (!cs.serverUrl || !cs.token) return;

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/vaults`,
        method: "POST",
        headers: {
          Authorization: `Bearer ${cs.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name }),
        throw: false,
      });

      if (res.status === 200) {
        new Notice(`Created remote vault "${name}".`);
        await this.handleConnectVault(name);
      } else {
        new Notice(
          `Failed to create vault: ${res.json?.error || "Unknown error"}`
        );
      }
    } catch (err: any) {
      new Notice(`Error creating vault: ${err?.message || err}`);
    }
  }

  private async handleConnectVault(vaultName: string, vaultOwner?: string) {
    const cs = this.plugin.settings.cloudsync;
    cs.vaultId = vaultName;

    if (
      vaultOwner &&
      vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
    ) {
      cs.vaultOwner = vaultOwner;
      const sharedPassword = window.prompt(
        `Connecting to shared vault "${vaultName}" (owned by ${vaultOwner}).\n\nIf this vault is end-to-end encrypted, enter the vault password provided by the owner (leave empty if unencrypted):`
      );
      if (sharedPassword !== null) {
        const clean = sharedPassword.trim();
        if (clean) {
          this.plugin.settings.password = clean;
          cs.encryptionKey = clean;
        }
      }
    } else {
      cs.vaultOwner = cs.username || "";
    }

    this.plugin.lastKnownRevision = 0;
    this.plugin.clearCachedClients();
    await this.plugin.saveSettings();

    new Notice(`Connected to remote vault "${vaultName}".`);
    this.onVaultChanged?.(vaultName);
    this.close();

    window.setTimeout(() => {
      this.plugin.syncRun("manual");
    }, 300);
  }

  private async handleDeleteVault(vaultName: string) {
    const cs = this.plugin.settings.cloudsync;
    if (!cs.serverUrl || !cs.token) return;

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/vaults/${encodeURIComponent(vaultName)}`,
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${cs.token}`,
        },
        throw: false,
      });

      if (res.status === 200) {
        new Notice(`Deleted remote vault "${vaultName}".`);
        if (cs.vaultId === vaultName) {
          cs.vaultId = "";
          this.plugin.clearCachedClients();
          await this.plugin.saveSettings();
          this.onVaultChanged?.("");
        }
        this.vaults = this.vaults.filter((v) => v.name !== vaultName);
        await this.fetchVaults();
        this.render();
      } else {
        new Notice(
          `Failed to delete vault: ${res.json?.error || "Unknown error"}`
        );
      }
    } catch (err: any) {
      new Notice(`Error deleting vault: ${err?.message || err}`);
    }
  }
}
