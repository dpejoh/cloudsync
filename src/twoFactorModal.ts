import { App, Modal, Notice, requestUrl } from "obsidian";
import QRCode from "qrcode";
import { generateTotpSecret } from "./authHelper";
import type CloudSyncPlugin from "./main";

export class TwoFactorModal extends Modal {
  plugin: CloudSyncPlugin;
  private step: "prompt" | "setup" | "verify";
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
    initialStep: "prompt" | "setup" = "prompt",
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
    contentEl.addClass("cloudsync-2fa-modal");

    if (this.step === "prompt") {
      this.renderPromptStep(contentEl);
    } else if (this.step === "setup") {
      this.renderSetupStep(contentEl);
    } else if (this.step === "verify") {
      this.renderVerifyStep(contentEl);
    }
  }

  // ---------------------------------------------------------------------------
  // Step 1: Interstitial Prompt ("Protect your account")
  // ---------------------------------------------------------------------------
  private renderPromptStep(contentEl: HTMLElement) {
    contentEl.createEl("h2", {
      text: "Protect your account",
      cls: "cloudsync-modal-title",
    });

    const descEl = contentEl.createDiv({ cls: "cloudsync-modal-desc" });
    descEl.createEl("p", {
      text: "To ensure you do not lose access to your account and to protect your encrypted notes, you will need to set up Two-Factor Authentication (2FA) now.",
    });
    descEl.createEl("p", {
      text: "This pairs CloudSync with an authenticator app (such as Google Authenticator, Aegis, 1Password, or Ente Auth) so only you can access your vault.",
      cls: "cloudsync-hint",
    });

    const buttonRow = contentEl.createDiv({ cls: "cloudsync-modal-btn-row" });

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

  // ---------------------------------------------------------------------------
  // Step 2: Dual Setup Methods (QR Code & Redacted Manual Key)
  // ---------------------------------------------------------------------------
  private renderSetupStep(contentEl: HTMLElement) {
    contentEl.createEl("h2", {
      text: "Set up Authenticator (2FA)",
      cls: "cloudsync-modal-title",
    });

    contentEl.createEl("p", {
      text: "Scan this QR code with your authenticator app on your phone or computer.",
      cls: "cloudsync-modal-desc",
    });

    // 1. QR Code Display
    if (this.qrDataUrl) {
      const qrWrapper = contentEl.createDiv({ cls: "cloudsync-qr-wrapper" });
      qrWrapper.createEl("img", {
        attr: { src: this.qrDataUrl, alt: "CloudSync 2FA QR Code" },
        cls: "cloudsync-qr-img",
      });
    }

    // 2. Manual Key Section (Redacted by default)
    const manualSection = contentEl.createDiv({
      cls: "cloudsync-manual-key-section",
    });
    manualSection.createEl("div", {
      text: "Or enter this secret key manually:",
      cls: "cloudsync-manual-label",
    });

    const keyBox = manualSection.createDiv({ cls: "cloudsync-key-box" });
    const formattedSecret =
      this.totpSecret.match(/.{1,4}/g)?.join(" ") || this.totpSecret;

    const secretDisplay = keyBox.createSpan({
      cls: "cloudsync-secret-text",
      text: this.isSecretVisible
        ? formattedSecret
        : "•••• •••• •••• •••• ••••",
    });

    const actionsDiv = keyBox.createDiv({ cls: "cloudsync-key-actions" });

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

    // Actions Row
    const buttonRow = contentEl.createDiv({ cls: "cloudsync-modal-btn-row" });

    const continueBtn = buttonRow.createEl("button", {
      cls: "mod-cta",
      text: "Continue to Verification →",
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

  // ---------------------------------------------------------------------------
  // Step 3: OTP Verification Challenge
  // ---------------------------------------------------------------------------
  private renderVerifyStep(contentEl: HTMLElement) {
    contentEl.createEl("h2", {
      text: "Verify Authenticator Code",
      cls: "cloudsync-modal-title",
    });

    contentEl.createEl("p", {
      text: "Enter the 6-digit code currently generated by your authenticator app to complete setup.",
      cls: "cloudsync-modal-desc",
    });

    if (this.errorMessage) {
      const errorEl = contentEl.createDiv({ cls: "cloudsync-error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = contentEl.createDiv({ cls: "cloudsync-auth-form" });

    const inputGroup = form.createDiv({ cls: "cloudsync-input-group" });
    const otpInputEl = inputGroup.createEl("input", {
      type: "text",
      cls: "cloudsync-text-input cloudsync-otp-input",
      value: this.otpInput,
      placeholder: "000000",
      attr: { maxlength: "6", autofocus: "true" },
    });

    otpInputEl.oninput = (e) => {
      this.otpInput = (e.target as HTMLInputElement).value
        .replace(/[^0-9]/g, "")
        .slice(0, 6);
      this.errorMessage = null;
    };

    otpInputEl.onkeydown = (e) => {
      if (e.key === "Enter") {
        this.handleVerify();
      }
    };

    // Focus input
    setTimeout(() => otpInputEl.focus(), 100);

    const buttonRow = contentEl.createDiv({ cls: "cloudsync-modal-btn-row" });

    const verifyBtn = buttonRow.createEl("button", {
      cls: "mod-cta",
      text: this.isLoading ? "Verifying..." : "Verify & Enable 2FA",
    });
    verifyBtn.disabled = this.isLoading;
    verifyBtn.onclick = () => this.handleVerify();

    const backBtn = buttonRow.createEl("button", {
      text: "← Back",
    });
    backBtn.disabled = this.isLoading;
    backBtn.onclick = () => {
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

      // Success!
      cs.has2FA = true;
      await this.plugin.saveSettings();
      new Notice("CloudSync: Two-factor authentication enabled successfully!");
      this.onFinished?.(true);
      this.close();
    } catch (err: any) {
      this.isLoading = false;
      this.errorMessage = `Verification failed: ${err?.message || err}`;
      this.render();
    }
  }
}
