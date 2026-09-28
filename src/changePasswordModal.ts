import { type App, Modal, Notice, Setting } from "obsidian";
import type CloudSyncPlugin from "./main";

export class ChangePasswordModal extends Modal {
  private plugin: CloudSyncPlugin;
  private current = "";
  private next = "";
  private confirmValue = "";
  private onDone?: () => void;

  constructor(app: App, plugin: CloudSyncPlugin, onDone?: () => void) {
    super(app);
    this.plugin = plugin;
    this.onDone = onDone;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.addClass("two-factor-modal");
    contentEl.createEl("h2", { text: "Change password", cls: "sub-modal-title" });
    contentEl.createEl("p", {
      text: "Your vault encryption keys are re-wrapped with the new password. Notes stay readable and other devices can keep syncing after signing in again.",
      cls: "modal-description",
    });

    new Setting(contentEl).setName("Current password").addText((text) => {
      text.inputEl.type = "password";
      text.onChange((value) => {
        this.current = value;
      });
    });
    new Setting(contentEl).setName("New password").addText((text) => {
      text.inputEl.type = "password";
      text.onChange((value) => {
        this.next = value;
      });
    });
    new Setting(contentEl).setName("Confirm new password").addText((text) => {
      text.inputEl.type = "password";
      text.onChange((value) => {
        this.confirmValue = value;
      });
    });

    const row = contentEl.createDiv({ cls: "modal-btn-row" });
    const saveBtn = row.createEl("button", { cls: "mod-cta", text: "Change password" });
    saveBtn.onclick = async () => {
      if (!this.current || !this.next) {
        new Notice("Please fill in all fields.");
        return;
      }
      if (this.next !== this.confirmValue) {
        new Notice("New passwords do not match.");
        return;
      }
      saveBtn.disabled = true;
      saveBtn.setText("Changing...");
      try {
        await this.plugin.keyManager.changePassword({
          oldPassword: this.current,
          newPassword: this.next,
        });
        new Notice("Password changed. Other devices must sign in again.");
        this.onDone?.();
        this.close();
      } catch (err: any) {
        saveBtn.disabled = false;
        saveBtn.setText("Change password");
        new Notice(`Failed to change password: ${err?.message || err}`);
      }
    };
    const cancelBtn = row.createEl("button", { text: "Cancel" });
    cancelBtn.onclick = () => this.close();
  }

  onClose() {
    this.contentEl.empty();
  }
}
