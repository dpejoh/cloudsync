import { type App, Modal, Notice } from "obsidian";

export class RecoveryKeyModal extends Modal {
  private recoveryKey: string;
  private isVisible = false;
  private onClosed?: () => void;

  constructor(app: App, recoveryKey: string, onClosed?: () => void) {
    super(app);
    this.recoveryKey = recoveryKey;
    this.onClosed = onClosed;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.addClass("two-factor-modal");

    contentEl.createEl("h2", {
      text: "Save your recovery key",
      cls: "sub-modal-title",
    });

    const descEl = contentEl.createDiv({ cls: "modal-description" });
    descEl.createEl("p", {
      text: "This key is the only way to reset your password if you lose access to your authenticator app. It is shown only once and is never sent to the server.",
    });
    descEl.createEl("p", {
      text: "Store it somewhere safe and offline. Anyone with this key can reset your account password.",
      cls: "input-hint",
    });

    const keyBox = contentEl.createDiv({ cls: "key-box" });
    const formatted =
      this.recoveryKey.match(/.{1,4}/g)?.join(" ") || this.recoveryKey;
    const display = keyBox.createSpan({
      cls: "secret-text",
      text: "•••• •••• •••• •••• ••••",
    });

    const actions = keyBox.createDiv({ cls: "key-actions" });
    const toggleBtn = actions.createEl("button", {
      cls: "mod-sm",
      text: "Show",
    });
    toggleBtn.onclick = () => {
      this.isVisible = !this.isVisible;
      display.setText(this.isVisible ? formatted : "•••• •••• •••• •••• ••••");
      toggleBtn.setText(this.isVisible ? "Hide" : "Show");
    };

    const copyBtn = actions.createEl("button", { cls: "mod-sm", text: "Copy" });
    copyBtn.onclick = async () => {
      await navigator.clipboard.writeText(this.recoveryKey);
      copyBtn.setText("Copied!");
      setTimeout(() => copyBtn.setText("Copy"), 2000);
    };

    const buttonRow = contentEl.createDiv({ cls: "modal-btn-row" });
    const doneBtn = buttonRow.createEl("button", {
      cls: "mod-cta",
      text: "I have saved my recovery key",
    });
    doneBtn.onclick = () => this.close();
  }

  onClose() {
    this.contentEl.empty();
    this.onClosed?.();
  }
}
