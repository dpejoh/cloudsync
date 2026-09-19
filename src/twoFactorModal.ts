import { App, Modal, Notice, requestUrl } from "obsidian";
import QRCode from "qrcode";
import { generateTotpSecret } from "./authHelper";
import { createOtpInput } from "./otpInput";
import type CloudSyncPlugin from "./main";

export class TwoFactorModal extends Modal {
  plugin: CloudSyncPlugin;
  private step: "intro" | "setup" | "verify";
  private totpSecret: string;
  private isSecretVisible = false;
  private otpInput = "";
  private errorMessage: string | null = null;
  private isLoading = false;
  private qrDataUrl = "";
  private onFinished?: (success: boolean) => void;

  constructor(
    app: App,
    plugin: CloudSyncPlugin,
    initialStep: "intro" | "setup" = "intro",
    onFinished?: (success: boolean) => void
  ) {
    super(app);
    this.plugin = plugin;
    this.step = initialStep;
    this.totpSecret = generateTotpSecret();
    this.onFinished = onFinished;
  }

  async onOpen() {
    await this.generateQr();
    this.render();
  }

  onClose() {
    this.contentEl.empty();
  }

  private async generateQr() {
    const username = this.plugin.settings.cloudsync.username || "user";
    const otpUri = `otpauth://totp/CloudSync:${encodeURIComponent(
      username
    )}?secret=${this.totpSecret}&issuer=CloudSync`;
    try {
      this.qrDataUrl = await QRCode.toDataURL(otpUri, {
        margin: 1,
        width: 180,
        color: {
          dark: "#000000",
          light: "#ffffff",
        },
      });
    } catch (err) {
      console.error("CloudSync: Failed to generate QR code", err);
    }
  }

  private render() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("two-factor-modal");

    if (this.step === "intro") {
      this.renderIntroStep(contentEl);
    } else if (this.step === "setup") {
      this.renderSetupStep(contentEl);
    } else if (this.step === "verify") {
      this.renderVerifyStep(contentEl);
    }
  }

  private renderIntroStep(contentEl: HTMLElement) {
    contentEl.createEl("h2", {
      text: "Protect your account",
      cls: "sub-modal-title",
    });

    const descEl = contentEl.createDiv({ cls: "modal-description" });
    descEl.createEl("p", {
      text: "To ensure you do not lose access to your account and to protect your encrypted notes, you will need to set up Two-Factor Authentication (2FA) now.",
    });
    descEl.createEl("p", {
      text: "Pair an authenticator app (such as Google Authenticator, Aegis, 1Password, or Ente Auth) to secure access to your account.",
      cls: "input-hint",
    });

    const buttonRow = contentEl.createDiv({ cls: "modal-btn-row" });

    const setupBtn = buttonRow.createEl("button", {
      cls: "mod-cta",
      text: "Set up 2FA",
    });
    setupBtn.onclick = () => {
      this.step = "setup";
      this.render();
    };

    const notNowBtn = buttonRow.createEl("button", {
      text: "Not now",
    });
    notNowBtn.onclick = () => {
      this.onFinished?.(false);
      this.close();
    };
  }

  private renderSetupStep(contentEl: HTMLElement) {
    contentEl.createEl("h2", {
      text: "Set up Authenticator (2FA)",
      cls: "sub-modal-title",
    });

    contentEl.createEl("p", {
      text: "Scan this QR code with your authenticator app on your phone or computer.",
      cls: "modal-description",
    });

        if (this.qrDataUrl) {
      const qrWrapper = contentEl.createDiv({ cls: "qr-wrapper" });
      qrWrapper.createEl("img", {
        attr: { src: this.qrDataUrl, alt: "CloudSync 2FA QR Code" },
        cls: "qr-img",
      });
    }

        const manualSection = contentEl.createDiv({
      cls: "manual-key-section",
    });
    manualSection.createEl("div", {
      text: "Or enter this secret key manually:",
      cls: "manual-key-label",
    });

    const keyBox = manualSection.createDiv({ cls: "key-box" });
    const formattedSecret =
      this.totpSecret.match(/.{1,4}/g)?.join(" ") || this.totpSecret;

    const secretDisplay = keyBox.createSpan({
      cls: "secret-text",
      text: this.isSecretVisible
        ? formattedSecret
        : "•••• •••• •••• •••• ••••",
    });

    const actionsDiv = keyBox.createDiv({ cls: "key-actions" });

    const toggleBtn = actionsDiv.createEl("button", {
      cls: "mod-sm",
      text: this.isSecretVisible ? "Hide" : "Show",
    });
    toggleBtn.onclick = () => {
      this.isSecretVisible = !this.isSecretVisible;
      secretDisplay.setText(
        this.isSecretVisible ? formattedSecret : "•••• •••• •••• •••• ••••"
      );
      toggleBtn.setText(this.isSecretVisible ? "Hide" : "Show");
    };

    const copyBtn = actionsDiv.createEl("button", {
      cls: "mod-sm",
      text: "Copy",
    });
    copyBtn.onclick = async () => {
      await navigator.clipboard.writeText(this.totpSecret);
      copyBtn.setText("Copied!");
      setTimeout(() => copyBtn.setText("Copy"), 2000);
    };

        const buttonRow = contentEl.createDiv({ cls: "modal-btn-row" });

    const continueBtn = buttonRow.createEl("button", {
      cls: "mod-cta",
      text: "Continue",
    });
    continueBtn.onclick = () => {
      this.step = "verify";
      this.errorMessage = null;
      this.render();
    };

    const cancelBtn = buttonRow.createEl("button", {
      text: "Set up later",
    });
    cancelBtn.onclick = () => {
      this.onFinished?.(false);
      this.close();
    };
  }

  private renderVerifyStep(contentEl: HTMLElement) {
    contentEl.createEl("h2", {
      text: "Verify Authenticator Code",
      cls: "sub-modal-title",
    });

    contentEl.createEl("p", {
      text: "Enter the 6-digit code currently generated by your authenticator app to complete setup.",
      cls: "modal-description",
    });

    if (this.errorMessage) {
      const errorEl = contentEl.createDiv({ cls: "error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = contentEl.createDiv({ cls: "auth-form" });

    createOtpInput(form, {
      length: 6,
      initialValue: this.otpInput,
      autoFocus: true,
      onChange: (code) => {
        this.otpInput = code;
        this.errorMessage = null;
      },
      onComplete: (code) => {
        this.otpInput = code;
        this.handleVerify();
      },
    });

    const verifyBtn = form.createEl("button", {
      cls: "mod-cta auth-submit-btn otp-action-btn",
      text: this.isLoading ? "Verifying..." : "Verify & Enable 2FA",
    });
    verifyBtn.disabled = this.isLoading;
    verifyBtn.onclick = () => this.handleVerify();

    const backRow = contentEl.createDiv({ cls: "switch-row" });
    const backLink = backRow.createEl("a", {
      cls: "inline-link",
      text: "← Back",
    });
    backLink.onclick = () => {
      this.step = "setup";
      this.errorMessage = null;
      this.render();
    };
  }

  private async handleVerify() {
    if (!this.otpInput || this.otpInput.length !== 6) {
      this.errorMessage = "Please enter the full 6-digit code from your app.";
      this.render();
      return;
    }

    this.isLoading = true;
    this.errorMessage = null;
    this.render();

    const cs = this.plugin.settings.cloudsync;
    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/user/setup-2fa`,
        method: "POST",
        headers: {
          Authorization: `Bearer ${cs.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          totpSecret: this.totpSecret,
          totpCode: this.otpInput,
        }),
        throw: false,
      });

      if (res.status !== 200) {
        this.isLoading = false;
        this.errorMessage =
          res.json?.error ||
          "Invalid verification code. Please check your authenticator app and try again.";
        this.render();
        return;
      }

            cs.has2FA = true;
      await this.plugin.saveSettings();
      new Notice("Two-factor authentication enabled.");
      this.onFinished?.(true);
      this.close();
    } catch (err: any) {
      this.isLoading = false;
      this.errorMessage = `Verification failed: ${err?.message || err}`;
      this.render();
    }
  }
}
