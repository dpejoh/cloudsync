import { App, Modal, Notice, Platform, requestUrl } from "obsidian";
import type CloudSyncPlugin from "./main";
import { confirmVaultRekey, runVaultRekey } from "./rotationUi";

export class VaultShareModal extends Modal {
  plugin: CloudSyncPlugin;
  vaultName: string;
  private shares: string[] = [];
  private isLoading = true;
  private isRotating = false;
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
        if (cs.scheme === 2) {
          try {
            const version = this.plugin.keyManager.vaultKeyVersion(this.vaultName) ?? 1;
            await this.plugin.keyManager.shareVaultKeyWith({
              vaultId: this.vaultName,
              version,
              recipientUsername: username,
            });
          } catch (err: any) {
            new Notice(
              `Invited, but delivering the vault key failed: ${err?.message || err}. Use "Copy vault encryption key" as a fallback.`,
              12000
            );
          }
        }
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
    if (!confirm(`Remove ${username} from "${this.vaultName}"?`)) return;

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

        if (
          !this.isRotating &&
          cs.scheme === 2 &&
          confirm(
            `Rotate the vault key now?\n\nThis permanently invalidates the key copy ${username} received. Other collaborators keep access automatically.`
          )
        ) {
          this.isRotating = true;
          this.render();
          try {
            await runVaultRekey(this.plugin, this.vaultName);
          } finally {
            this.isRotating = false;
            await this.fetchShares();
            this.render();
          }
        }
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

    if (this.isRotating) {
      const rotateBox = contentEl.createDiv({ cls: "error-banner" });
      rotateBox.setText(
        "Re-keying this vault... keep Obsidian open until it finishes. Sync is paused for all devices meanwhile."
      );
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
        if (Platform.isMobile) {
          userRow.addClass("is-fully-rounded");
          userRow.style.borderRadius = "9999px";
        }
        const userInfo = userRow.createDiv({ cls: "share-user-info" });
        const avatar = userInfo.createDiv({ cls: "share-user-avatar" });

        const serverUrl = this.plugin.settings.cloudsync.serverUrl;
        const initial = user.charAt(0).toUpperCase();

        if (serverUrl) {
          const img = avatar.createEl("img", {
            cls: "share-user-avatar-img",
            attr: {
              src: `${serverUrl}/api/user/avatar/${encodeURIComponent(user)}`,
              alt: user,
            },
          });
          const fallback = avatar.createSpan({
            cls: "share-user-avatar-fallback",
            text: initial,
          });
          fallback.style.display = "none";

          img.onload = () => {
            img.style.display = "block";
            fallback.style.display = "none";
          };
          img.onerror = () => {
            img.remove();
            fallback.style.display = "flex";
          };
        } else {
          avatar.setText(initial);
        }

        const nameSpan = userInfo.createSpan({ text: user, cls: "share-username" });
        if (serverUrl) {
          requestUrl({
            url: `${serverUrl}/api/user/profile/${encodeURIComponent(user)}`,
            method: "GET",
            throw: false,
          })
            .then((res) => {
              if (
                res.status === 200 &&
                res.json?.displayName &&
                res.json.displayName !== user
              ) {
                nameSpan.empty();
                nameSpan.createSpan({
                  text: res.json.displayName,
                  cls: "share-display-name",
                });
                nameSpan.createSpan({
                  text: ` (@${user})`,
                  cls: "share-handle",
                });
              }
            })
            .catch(() => {});
        }

        const removeBtn = userRow.createEl("button", {
          cls: "share-remove-btn mod-destructive",
          text: "Remove",
        });
        removeBtn.disabled = this.isRotating;
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
    addBtn.disabled = this.isRotating;
    addBtn.onclick = () => this.inviteUser();

    // Footer with Done button
    const footer = contentEl.createDiv({ cls: "modal-button-container" });
    const rotateBtn = footer.createEl("button", {
      cls: "mod-warning",
      text: "Re-key vault key",
    });
    rotateBtn.disabled = this.isRotating;
    rotateBtn.onclick = () => this.startRotation();
    footer.createEl("button", { text: "Done" }, (btn) => {
      btn.onclick = () => this.close();
    });
  }

  /**
   * Explicitly rotate the vault key: new random key, full re-encryption, old
   * history/trash purged, remaining collaborators get the new key automatically.
   */
  private async startRotation() {
    const cs = this.plugin.settings.cloudsync;
    if (cs.scheme !== 2 || this.isRotating) return;
    if (!confirmVaultRekey()) return;

    this.isRotating = true;
    this.render();
    try {
      await runVaultRekey(this.plugin, this.vaultName);
    } finally {
      this.isRotating = false;
      await this.fetchShares();
      this.render();
    }
  }
}
