import { App, Modal, Notice, requestUrl } from "obsidian";
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

  onOpen() {
    this.setTitle(`Manage sharing for "${this.vaultName}"`);
    this.contentEl.addClass("vault-share-modal");
    this.isLoading = true;
    this.render();
    this.fetchShares().then(() => this.render());
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

      if (res.status === 200 && Array.isArray(res.json?.shares)) {
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
        new Notice(`Shared "${this.vaultName}" with ${username}.`);
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

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "This remote vault is currently shared with the following people:",
    });

    if (this.errorMessage) {
      const errBox = contentEl.createDiv({ cls: "error-banner" });
      errBox.setText(this.errorMessage);
    }

    const sharesContainerEl = contentEl.createDiv({
      cls: "vault-shares-list",
    });

    if (this.isLoading) {
      sharesContainerEl.createDiv({
        cls: "empty-shares-notice",
        text: "Loading collaborators...",
      });
    } else if (this.shares.length === 0) {
      sharesContainerEl.createDiv({
        cls: "empty-shares-notice",
        text: "This remote vault is not currently shared with anyone.",
      });
    } else {
      for (const user of this.shares) {
        const userRow = sharesContainerEl.createDiv({
          cls: "share-user-row",
        });
        userRow.createSpan({ text: user, cls: "share-username" });
        const removeBtn = userRow.createEl("button", {
          cls: "share-remove-btn mod-destructive",
          text: "Remove",
        });
        removeBtn.onclick = () => this.removeShare(user);
      }
    }

    // Invite user compact row
    const inviteSection = contentEl.createDiv({ cls: "invite-section" });
    inviteSection.createEl("div", {
      cls: "invite-section-title",
      text: "Invite user",
    });

    const inviteRow = inviteSection.createDiv({ cls: "invite-row" });
    const inputEl = inviteRow.createEl("input", {
      type: "text",
      placeholder: "Enter their username...",
      cls: "invite-input",
      value: this.inviteUsername,
    });
    inputEl.oninput = (e) => {
      this.inviteUsername = (e.target as HTMLInputElement).value;
      this.errorMessage = null;
    };
    inputEl.onkeydown = (e) => {
      if (e.key === "Enter") this.inviteUser();
    };

    const addBtn = inviteRow.createEl("button", {
      cls: "mod-cta invite-btn",
      text: "Add",
    });
    addBtn.onclick = () => this.inviteUser();

    // Footer with Done button
    const footer = contentEl.createDiv({ cls: "modal-button-container" });
    footer.createEl("button", { text: "Done" }, (btn) => {
      btn.onclick = () => this.close();
    });
  }
}
