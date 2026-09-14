import { App, Modal, Notice, Setting, requestUrl } from "obsidian";
import type CloudSyncPlugin from "./main";

export class VaultShareModal extends Modal {
  plugin: CloudSyncPlugin;
  vaultName: string;
  private shares: string[] = [];
  private isLoading = true;
  private inviteUsername = "";
  private errorMessage: string | null = null;

  constructor(app: App, plugin: CloudSyncPlugin, vaultName: string) {
    super(app);
    this.plugin = plugin;
    this.vaultName = vaultName;
  }

  async onOpen() {
    this.contentEl.addClass("sync-vault-share-container");
    await this.fetchShares();
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private async fetchShares() {
    const cs = this.plugin.settings.cloudsync;
    if (!cs.serverUrl || !cs.token) return;

    this.isLoading = true;
    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/shares?vault=${encodeURIComponent(this.vaultName)}`,
        method: "GET",
        headers: {
          Authorization: `Bearer ${cs.token}`,
        },
        throw: false,
      });

      if (res.status === 200 && res.json?.shares) {
        this.shares = res.json.shares;
      } else {
        this.shares = [];
      }
    } catch (err) {
      console.error("Failed to fetch vault shares:", err);
      this.shares = [];
    } finally {
      this.isLoading = false;
    }
  }

  private async inviteUser() {
    const username = this.inviteUsername.trim();
    if (!username) return;

    const cs = this.plugin.settings.cloudsync;
    this.errorMessage = null;

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/shares?vault=${encodeURIComponent(this.vaultName)}`,
        method: "POST",
        headers: {
          Authorization: `Bearer ${cs.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ inviteUsername: username }),
        throw: false,
      });

      if (res.status === 200) {
        new Notice(`Shared "${this.vaultName}" with ${username}!`);
        this.inviteUsername = "";
        await this.fetchShares();
        this.render();
      } else {
        this.errorMessage = res.json?.error || "Failed to invite user.";
        this.render();
      }
    } catch (err: any) {
      this.errorMessage = `Error: ${err?.message || err}`;
      this.render();
    }
  }

  private async removeShare(username: string) {
    const cs = this.plugin.settings.cloudsync;
    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/sync/shares?vault=${encodeURIComponent(this.vaultName)}&username=${encodeURIComponent(username)}`,
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${cs.token}`,
        },
        throw: false,
      });

      if (res.status === 200) {
        new Notice(`Removed ${username} from "${this.vaultName}".`);
        await this.fetchShares();
        this.render();
      } else {
        new Notice(res.json?.error || "Failed to remove user.");
      }
    } catch (err: any) {
      new Notice(`Error: ${err?.message || err}`);
    }
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", {
      text: `Manage sharing for “${this.vaultName}”`,
      cls: "modal-title",
    });

    contentEl.createEl("p", {
      cls: "u-muted",
      text: "This remote vault is currently shared with the following people:",
    });

    if (this.errorMessage) {
      const errBox = contentEl.createDiv({ cls: "cloudsync-error-banner" });
      errBox.setText(this.errorMessage);
    }

    const sharesContainerEl = contentEl.createDiv({
      cls: "sync-vault-shares-list-item-container",
    });

    if (this.isLoading) {
      sharesContainerEl.createEl("p", {
        cls: "u-muted",
        text: "Loading collaborators...",
      });
    } else if (this.shares.length === 0) {
      sharesContainerEl.createEl("p", {
        cls: "u-muted",
        text: "This remote vault is not currently shared with anyone.",
      });
    } else {
      for (const user of this.shares) {
        const userRow = sharesContainerEl.createDiv({
          cls: "cloudsync-share-user-row",
        });
        userRow.createSpan({ text: user, cls: "cloudsync-share-username" });
        const removeBtn = userRow.createEl("button", {
          cls: "cloudsync-share-remove-btn mod-destructive",
          text: "Remove",
        });
        removeBtn.onclick = () => this.removeShare(user);
      }
    }

    // Invite user input row
    const inviteSetting = new Setting(contentEl)
      .setName("Invite user")
      .addText((text) => {
        text
          .setPlaceholder("Enter their username...")
          .setValue(this.inviteUsername)
          .onChange((val) => {
            this.inviteUsername = val;
            this.errorMessage = null;
          });
        text.inputEl.addEventListener("keydown", (e) => {
          if (e.key === "Enter") this.inviteUser();
        });
      })
      .addButton((btn) => {
        btn
          .setButtonText("Add")
          .setCta()
          .onClick(() => this.inviteUser());
      });

    // Done button at bottom right
    const footer = contentEl.createDiv({ cls: "modal-button-container" });
    footer.createEl("button", { text: "Done" }, (btn) => {
      btn.onclick = () => this.close();
    });
  }
}
