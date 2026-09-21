import { App, Modal, Notice, requestUrl } from "obsidian";
import type CloudSyncPlugin from "./main";

export class EditProfileModal extends Modal {
  plugin: CloudSyncPlugin;
  private displayName: string = "";
  private isSaving = false;
  private onSaveCallback?: () => void;

  constructor(app: App, plugin: CloudSyncPlugin, onSaveCallback?: () => void) {
    super(app);
    this.plugin = plugin;
    this.onSaveCallback = onSaveCallback;
    const cs = this.plugin.settings.cloudsync;
    this.displayName = cs.displayName || cs.username || "";
  }

  onOpen() {
    this.setTitle("Edit profile");
    this.contentEl.addClass("edit-profile-modal");
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();
    const cs = this.plugin.settings.cloudsync;

    // Avatar section
    const avatarSection = contentEl.createDiv({ cls: "profile-edit-avatar-section" });
    const previewContainer = avatarSection.createDiv({ cls: "profile-avatar-preview" });
    const initial = (this.displayName || cs.username || "U").charAt(0).toUpperCase();

    if (cs.serverUrl && cs.username) {
      const avatarImg = previewContainer.createEl("img", {
        attr: {
          src: `${cs.serverUrl}/api/user/avatar/${encodeURIComponent(cs.username)}?t=${Date.now()}`,
          alt: cs.username,
        },
      });
      const fallbackSpan = previewContainer.createSpan({ text: initial });
      fallbackSpan.style.display = "none";

      avatarImg.onload = () => {
        avatarImg.style.display = "block";
        fallbackSpan.style.display = "none";
      };
      avatarImg.onerror = () => {
        avatarImg.remove();
        fallbackSpan.style.display = "flex";
      };
    } else {
      previewContainer.createSpan({ text: initial });
    }

    const avatarActions = avatarSection.createDiv({ cls: "profile-avatar-actions" });

    // Hidden file input
    const fileInput = avatarActions.createEl("input", {
      type: "file",
      attr: {
        accept: "image/png,image/jpeg,image/webp,image/gif",
        style: "display: none;",
      },
    });

    fileInput.onchange = async () => {
      const file = fileInput.files?.[0];
      if (!file) return;

      const MAX_SIZE = 512 * 1024;
      if (file.size > MAX_SIZE) {
        new Notice("Avatar image exceeds 512 KB limit.");
        fileInput.value = "";
        return;
      }

      const allowedTypes = ["image/png", "image/jpeg", "image/webp", "image/gif"];
      if (!allowedTypes.includes(file.type)) {
        new Notice("Invalid image format. Supported formats: PNG, JPEG, WebP, GIF.");
        fileInput.value = "";
        return;
      }

      try {
        const buffer = await file.arrayBuffer();
        const res = await requestUrl({
          url: `${cs.serverUrl}/api/user/avatar`,
          method: "POST",
          headers: {
            Authorization: `Bearer ${cs.token}`,
            "Content-Type": file.type,
          },
          body: buffer,
          throw: false,
        });

        if (res.status === 200) {
          new Notice("Profile picture updated.");
          cs.hasAvatar = true;
          await this.plugin.saveSettings();
          this.render();
          this.onSaveCallback?.();
        } else {
          let errorMsg = `Upload failed (${res.status})`;
          try {
            if (res.json?.error) errorMsg = res.json.error;
          } catch {
            if (res.text && res.text.length < 100) errorMsg = res.text;
          }
          new Notice(errorMsg);
        }
      } catch (err: any) {
        new Notice(`Error uploading avatar: ${err?.message || err}`);
      }
    };

    const changeBtn = avatarActions.createEl("button", {
      text: "Change photo",
      cls: "mod-cta",
    });
    changeBtn.onclick = () => fileInput.click();

    if (cs.hasAvatar) {
      const removeBtn = avatarActions.createEl("button", {
        text: "Remove photo",
        cls: "mod-destructive",
      });
      removeBtn.onclick = async () => {
        try {
          const res = await requestUrl({
            url: `${cs.serverUrl}/api/user/avatar`,
            method: "DELETE",
            headers: {
              Authorization: `Bearer ${cs.token}`,
            },
            throw: false,
          });

          if (res.status === 200) {
            new Notice("Profile picture removed.");
            cs.hasAvatar = false;
            await this.plugin.saveSettings();
            this.render();
            this.onSaveCallback?.();
          } else {
            let errorMsg = `Remove failed (${res.status})`;
            try {
              if (res.json?.error) errorMsg = res.json.error;
            } catch {
              if (res.text && res.text.length < 100) errorMsg = res.text;
            }
            new Notice(errorMsg);
          }
        } catch (err: any) {
          new Notice(`Error removing avatar: ${err?.message || err}`);
        }
      };
    }

    // Name field
    const nameSection = contentEl.createDiv({ cls: "profile-edit-name-section" });
    nameSection.createEl("label", {
      cls: "setting-item-name",
      text: "Display name",
    });
    nameSection.createEl("div", {
      cls: "setting-item-description",
      text: "Friendly name shown to other collaborators (leaves username handle unchanged).",
    });

    const nameInput = nameSection.createEl("input", {
      type: "text",
      cls: "profile-edit-name-input",
      value: this.displayName,
      placeholder: "e.g. David Pejoh",
    });
    nameInput.oninput = (e) => {
      this.displayName = (e.target as HTMLInputElement).value;
    };
    nameInput.onkeydown = (e) => {
      if (e.key === "Enter") this.saveProfile();
    };

    // Username handle (read only)
    const handleSection = contentEl.createDiv({ cls: "profile-edit-handle-section" });
    handleSection.createEl("div", {
      cls: "setting-item-description",
      text: `Username handle: @${cs.username}`,
    });

    // Action buttons in footer
    const footer = contentEl.createDiv({ cls: "modal-button-container" });
    const cancelBtn = footer.createEl("button", { text: "Cancel" });
    cancelBtn.onclick = () => this.close();

    const saveBtn = footer.createEl("button", {
      text: this.isSaving ? "Saving..." : "Save changes",
      cls: "mod-cta",
    });
    saveBtn.onclick = () => this.saveProfile();
  }

  private async saveProfile() {
    if (this.isSaving) return;
    this.isSaving = true;

    const cs = this.plugin.settings.cloudsync;
    const trimmedName = this.displayName.trim();

    try {
      if (cs.serverUrl && cs.token) {
        const res = await requestUrl({
          url: `${cs.serverUrl}/api/user/profile`,
          method: "POST",
          headers: {
            Authorization: `Bearer ${cs.token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ displayName: trimmedName }),
          throw: false,
        });

        if (res.status === 200 && res.json?.displayName !== undefined) {
          cs.displayName = res.json.displayName;
        } else {
          cs.displayName = trimmedName;
        }
      } else {
        cs.displayName = trimmedName;
      }

      await this.plugin.saveSettings();
      new Notice("Profile updated successfully.");
      this.onSaveCallback?.();
      this.close();
    } catch (err: any) {
      new Notice(`Failed to update profile: ${err?.message || err}`);
    } finally {
      this.isSaving = false;
    }
  }
}
