import {
  type App,
  Notice,
  PluginSettingTab,
  Setting,
  Platform,
  requestUrl,
} from "obsidian";
import {
  deriveZeroKnowledgeKeys,
  deriveRecoveryVerifier,
} from "./authHelper";
import { OBSIDIAN_LOGO_PNG } from "./assets/logo";
import {
  type CloudSyncConfig,
  DEFAULT_CLOUDSYNC_CONFIG,
  type RemotelySavePluginSettings,
} from "./baseTypes";
import {
  initDeviceIdentity,
  backupDeviceSettings,
  restoreDeviceSettings,
} from "./deviceSettings";
import { FakeFsWorker, type DeviceInfo } from "./fsWorker";
import { TwoFactorModal } from "./twoFactorModal";
import { VaultShareModal } from "./vaultShareModal";
import { VaultPickerModal } from "./vaultPickerModal";
import { ExcludedFoldersModal } from "./excludedFoldersModal";
import { DeletedFilesModal } from "./deletedFilesModal";
import { SyncLogModal } from "./syncLogModal";
import { EditProfileModal } from "./editProfileModal";
import { destroyDBs } from "./localdb";
import { createOtpInput } from "./otpInput";
import type CloudSyncPlugin from "./main";

function getResponseError(res: any, fallback: string): string {
  try {
    return res?.json?.error || res?.text || fallback;
  } catch {
    return res?.text || fallback;
  }
}

export class CloudSyncSettingTab extends PluginSettingTab {
  plugin: CloudSyncPlugin;

  // View state
  private isRegisterMode = false;
  private isRecoveryMode = false;
  private requires2FA = false;
  private recoveryMethod: "totp" | "key" = "totp";

  // Inputs
  private serverUrlInput = "";
  private usernameInput = "";
  private passwordInput = "";
  private totpCodeInput = "";
  private recoveryKeyInput = "";

  private errorMessage: string | null = null;
  private isLoading = false;
  private storageUsedBytes: number | null = null;

  constructor(app: App, plugin: CloudSyncPlugin) {
    super(app, plugin);
    this.plugin = plugin;
    this.serverUrlInput = this.plugin.settings.cloudsync.serverUrl || "";
  }

  async display(): Promise<void> {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.addClass("sync-settings-page");

    const cs = this.plugin.settings.cloudsync;
    const isConfigured = Boolean(cs.serverUrl);
    const isAuthenticated =
      Boolean(cs.token) &&
      Boolean(cs.username || cs.email || cs.userId === "default");

    if (!isConfigured) {
      containerEl.addClass("is-auth-active");
      this.renderServerUrlView(containerEl);
    } else if (!isAuthenticated) {
      containerEl.addClass("is-auth-active");
      this.renderAuthView(containerEl);
    } else {
      containerEl.removeClass("is-auth-active");
      await this.renderLoggedInView(containerEl);
    }
  }

  hide(): void {
    super.hide();
    this.containerEl.removeClass("is-auth-active");
    this.containerEl.removeClass("sync-settings-page");
  }

  private renderServerUrlView(containerEl: HTMLElement) {
    const authWrapper = containerEl.createDiv({ cls: "auth-wrapper" });
    const authBox = authWrapper.createDiv({ cls: "auth-card" });

    const logoEl = authBox.createDiv({ cls: "auth-logo" });
    logoEl.createEl("img", {
      cls: "auth-logo-img",
      attr: { src: OBSIDIAN_LOGO_PNG, alt: "Logo" },
    });

    authBox.createDiv({
      cls: "auth-title",
      text: "Connect to sync server",
    });
    authBox.createDiv({
      cls: "auth-subtitle",
      text: "Enter your Cloudflare Worker or Private VPS server URL to begin.",
    });

    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "auth-form" });

    const urlGroup = form.createDiv({ cls: "input-group" });
    urlGroup.createEl("label", {
      text: "Sync Server URL",
      cls: "input-label",
    });
    const urlInputEl = urlGroup.createEl("input", {
      type: "url",
      cls: "auth-input",
      value: this.serverUrlInput,
      placeholder: "https://my-sync.workers.dev or https://sync.myvps.com",
    });
    urlInputEl.oninput = (e) => {
      this.serverUrlInput = (e.target as HTMLInputElement).value.trim();
      this.errorMessage = null;
    };
    urlInputEl.onkeydown = (e) => {
      if (e.key === "Enter") {
        this.handleConnectWorker();
      }
    };

    const connectBtn = form.createEl("button", {
      cls: "mod-cta auth-submit-btn",
      text: this.isLoading ? "Connecting..." : "Connect to Server",
    });
    connectBtn.disabled = this.isLoading;
    connectBtn.onclick = () => {
      this.handleConnectWorker();
    };
  }

  private async handleConnectWorker() {
    const url = (this.serverUrlInput || "").trim().replace(/\/+$/, "");
    if (!url || !url.startsWith("http")) {
      this.errorMessage = "Please enter a valid server URL starting with http:// or https://";
      this.display();
      return;
    }

    this.isLoading = true;
    this.errorMessage = null;
    this.display();

    try {
      const infoRes = await requestUrl({
        url: `${url}/api/info`,
        method: "GET",
        throw: false,
      });

      if (infoRes.status !== 200 || !infoRes.json?.service) {
        // Fallback probe root /
        const rootRes = await requestUrl({
          url: `${url}/`,
          method: "GET",
          throw: false,
        });

        if (rootRes.status !== 200 || !rootRes.json?.service) {
          throw new Error("Target server does not appear to be a CloudSync server.");
        }
      }

      const mode =
        infoRes.json?.mode === "single" ? "single" : "multi";

      this.plugin.settings.cloudsync.serverUrl = url;
      this.plugin.settings.cloudsync.mode = mode;
      await this.plugin.saveSettings();

      this.isLoading = false;
      this.errorMessage = null;
      this.display();
    } catch (err: any) {
      this.isLoading = false;
      this.errorMessage = `Cannot connect to worker: ${
        err?.message || "Ensure the worker is deployed and URL is correct."
      }`;
      this.display();
    }
  }

  private renderAuthView(containerEl: HTMLElement) {
    const cs = this.plugin.settings.cloudsync;
    const isSingleMode = cs.mode === "single";

    const authWrapper = containerEl.createDiv({ cls: "auth-wrapper" });
    const authBox = authWrapper.createDiv({ cls: "auth-card" });

    const logoEl = authBox.createDiv({ cls: "auth-logo" });
    logoEl.createEl("img", {
      cls: "auth-logo-img",
      attr: { src: OBSIDIAN_LOGO_PNG, alt: "Logo" },
    });

    if (this.requires2FA) {
      this.render2FAView(authBox);
      return;
    }

    if (isSingleMode) {
      authBox.createDiv({
        cls: "auth-title",
        text: "Unlock account",
      });
      authBox.createDiv({
        cls: "auth-subtitle",
        text: `Server: ${cs.serverUrl}`,
      });
    } else if (this.isRecoveryMode) {
      authBox.createDiv({
        cls: "auth-title",
        text: "Reset your password",
      });
      authBox.createDiv({
        cls: "auth-subtitle",
        text:
          this.recoveryMethod === "totp"
            ? "Enter your username, 2FA code from your authenticator app, and new password."
            : "Enter your username and recovery key to set a new password.",
      });
    } else if (this.isRegisterMode) {
      authBox.createDiv({
        cls: "auth-title",
        text: "Create an account",
      });
      authBox.createDiv({
        cls: "auth-subtitle",
        text: `Server: ${cs.serverUrl}`,
      });
    } else {
      authBox.createDiv({
        cls: "auth-title",
        text: "Sign in",
      });
      authBox.createDiv({
        cls: "auth-subtitle",
        text: `Server: ${cs.serverUrl}`,
      });
    }

    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "auth-form" });

    if (isSingleMode) {
      const passwordGroup = form.createDiv({ cls: "input-group" });
      passwordGroup.createEl("label", {
        text: "Master Password",
        cls: "input-label",
      });
      const passwordInputEl = passwordGroup.createEl("input", {
        type: "password",
        cls: "auth-input",
        value: this.passwordInput,
        placeholder: "Enter master password",
      });
      passwordInputEl.oninput = (e) => {
        this.passwordInput = (e.target as HTMLInputElement).value;
        this.errorMessage = null;
      };
      passwordInputEl.onkeydown = (e) => {
        if (e.key === "Enter") this.handleSingleLogin();
      };

      const unlockBtn = form.createEl("button", {
        cls: "mod-cta auth-submit-btn",
        text: this.isLoading ? "Unlocking..." : "Connect & Sync",
      });
      unlockBtn.disabled = this.isLoading;
      unlockBtn.onclick = () => this.handleSingleLogin();
    } else if (this.isRecoveryMode) {
      const userGroup = form.createDiv({ cls: "input-group" });
      userGroup.createEl("label", { text: "Username", cls: "input-label" });
      const userInputEl = userGroup.createEl("input", {
        type: "text",
        cls: "auth-input",
        value: this.usernameInput,
        placeholder: "username",
      });
      userInputEl.oninput = (e) => {
        this.usernameInput = (e.target as HTMLInputElement).value.trim();
        this.errorMessage = null;
      };

      if (this.recoveryMethod === "totp") {
        const totpGroup = form.createDiv({ cls: "input-group" });
        totpGroup.createEl("label", {
          text: "2FA Verification Code",
          cls: "input-label",
        });
        createOtpInput(totpGroup, {
          length: 6,
          initialValue: this.totpCodeInput,
          autoFocus: false,
          onChange: (code) => {
            this.totpCodeInput = code;
            this.errorMessage = null;
          },
        });
      } else {
        const recGroup = form.createDiv({ cls: "input-group" });
        recGroup.createEl("label", {
          text: "Recovery Key",
          cls: "input-label",
        });
        const recInputEl = recGroup.createEl("input", {
          type: "text",
          cls: "auth-input",
          value: this.recoveryKeyInput,
          placeholder: "SYNC-XXXX-XXXX-XXXX-XXXX",
        });
        recInputEl.oninput = (e) => {
          this.recoveryKeyInput = (e.target as HTMLInputElement).value.trim();
          this.errorMessage = null;
        };
      }

      const newPassGroup = form.createDiv({ cls: "input-group" });
      newPassGroup.createEl("label", {
        text: "New Password",
        cls: "input-label",
      });
      const newPassInputEl = newPassGroup.createEl("input", {
        type: "password",
        cls: "auth-input",
        value: this.passwordInput,
        placeholder: "••••••••",
      });
      newPassInputEl.oninput = (e) => {
        this.passwordInput = (e.target as HTMLInputElement).value;
        this.errorMessage = null;
      };
      newPassInputEl.onkeydown = (e) => {
        if (e.key === "Enter") this.handleRecoverySubmit();
      };

      const resetBtn = form.createEl("button", {
        cls: "mod-cta auth-submit-btn",
        text: this.isLoading ? "Resetting..." : "Reset Password & Sign In",
      });
      resetBtn.disabled = this.isLoading;
      resetBtn.onclick = () => this.handleRecoverySubmit();

      const switchMethodRow = authBox.createDiv({ cls: "switch-row" });
      const switchMethodLink = switchMethodRow.createEl("a", {
        cls: "inline-link",
        text:
          this.recoveryMethod === "totp"
            ? "Have a recovery key instead? Use recovery key"
            : "Have an authenticator app? Use 2FA code instead",
      });
      switchMethodLink.onclick = () => {
        this.recoveryMethod = this.recoveryMethod === "totp" ? "key" : "totp";
        this.errorMessage = null;
        this.display();
      };

      const backRow = authBox.createDiv({ cls: "switch-row" });
      const backLink = backRow.createEl("a", {
        cls: "inline-link",
        text: "← Back to Sign in",
      });
      backLink.onclick = () => {
        this.isRecoveryMode = false;
        this.errorMessage = null;
        this.display();
      };
    } else {
      const userGroup = form.createDiv({ cls: "input-group" });
      userGroup.createEl("label", { text: "Username", cls: "input-label" });
      const userInputEl = userGroup.createEl("input", {
        type: "text",
        cls: "auth-input",
        value: this.usernameInput,
        placeholder: "username",
      });
      userInputEl.oninput = (e) => {
        this.usernameInput = (e.target as HTMLInputElement).value.trim();
        this.errorMessage = null;
      };

      const passGroup = form.createDiv({ cls: "input-group" });
      const passLabelRow = passGroup.createDiv({ cls: "label-row" });
      passLabelRow.createEl("label", {
        text: "Password",
        cls: "input-label",
      });

      if (!this.isRegisterMode) {
        const forgotLink = passLabelRow.createEl("span", {
          cls: "forgot-link",
          text: "Forgot password?",
        });
        forgotLink.onclick = () => {
          this.isRecoveryMode = true;
          this.errorMessage = null;
          this.display();
        };
      }

      const passInputEl = passGroup.createEl("input", {
        type: "password",
        cls: "auth-input",
        value: this.passwordInput,
      });
      passInputEl.oninput = (e) => {
        this.passwordInput = (e.target as HTMLInputElement).value;
        this.errorMessage = null;
      };
      passInputEl.onkeydown = (e) => {
        if (e.key === "Enter") this.handleMultiAuthSubmit();
      };

      const submitBtn = form.createEl("button", {
        cls: "mod-cta auth-submit-btn",
        text: this.isLoading
          ? "Connecting..."
          : this.isRegisterMode
          ? "Create account"
          : "Sign in",
      });
      submitBtn.disabled = this.isLoading;
      submitBtn.onclick = () => this.handleMultiAuthSubmit();

      const switchRow = authBox.createDiv({ cls: "switch-row" });
      if (!this.isRegisterMode) {
        switchRow.createSpan({ text: "Don’t have an account? " });
        const switchLink = switchRow.createEl("a", {
          cls: "inline-link",
          text: "Create an account",
        });
        switchLink.onclick = () => {
          this.isRegisterMode = true;
          this.errorMessage = null;
          this.display();
        };
      } else {
        switchRow.createSpan({ text: "Already have an account? " });
        const switchLink = switchRow.createEl("a", {
          cls: "inline-link",
          text: "Sign in",
        });
        switchLink.onclick = () => {
          this.isRegisterMode = false;
          this.errorMessage = null;
          this.display();
        };
      }
    }

    const changeUrlRow = authBox.createDiv({ cls: "switch-row" });
    changeUrlRow.style.marginTop = "14px";
    const changeUrlLink = changeUrlRow.createEl("a", {
      cls: "inline-link",
      text: "Change Worker URL",
    });
    changeUrlLink.onclick = async () => {
      this.plugin.settings.cloudsync.serverUrl = "";
      await this.plugin.saveSettings();
      this.serverUrlInput = "";
      this.errorMessage = null;
      this.display();
    };
  }

  private render2FAView(authBox: HTMLElement) {
    authBox.createDiv({
      cls: "auth-title",
      text: "Two-factor authentication",
    });
    authBox.createDiv({
      cls: "auth-subtitle",
      text: `Enter the 6-digit code from your authenticator app for "${this.usernameInput}".`,
    });

    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "auth-form" });

    createOtpInput(form, {
      length: 6,
      initialValue: this.totpCodeInput,
      autoFocus: true,
      onChange: (code) => {
        this.totpCodeInput = code;
        this.errorMessage = null;
      },
      onComplete: (code) => {
        this.totpCodeInput = code;
        this.handleMultiAuthSubmit();
      },
    });

    const verifyBtn = form.createEl("button", {
      cls: "mod-cta auth-submit-btn otp-action-btn",
      text: this.isLoading ? "Verifying..." : "Verify & Sign in",
    });
    verifyBtn.disabled = this.isLoading;
    verifyBtn.onclick = () => this.handleMultiAuthSubmit();

    const backRow = authBox.createDiv({ cls: "switch-row" });
    const backLink = backRow.createEl("a", {
      cls: "inline-link",
      text: "← Back to Sign in",
    });
    backLink.onclick = () => {
      this.requires2FA = false;
      this.totpCodeInput = "";
      this.errorMessage = null;
      this.display();
    };
  }

  private async handleSingleLogin() {
    if (!this.passwordInput) {
      this.errorMessage = "Please enter your master password.";
      this.display();
      return;
    }

    this.isLoading = true;
    this.errorMessage = null;
    this.display();

    const cs = this.plugin.settings.cloudsync;
    try {
      const { authVerifier, encryptionKey } = await deriveZeroKnowledgeKeys(
        "default",
        this.passwordInput
      );

      const res = await requestUrl({
        url: `${cs.serverUrl}/api/auth/single-login`,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ verifier: authVerifier }),
        throw: false,
      });

      if (res.status !== 200) {
        this.errorMessage = res.json?.error || "Invalid master password.";
        this.isLoading = false;
        this.display();
        return;
      }

      cs.token = res.json.token;
      cs.userId = "default";
      cs.username = "Owner";
      cs.vaultId = this.app.vault.getName();
      cs.encryptionKey = encryptionKey;
      this.plugin.settings.password = encryptionKey;
      this.plugin.settings.encryptionMethod = "rclone-base64";

      await this.plugin.saveSettings();
      await this.plugin.autoRegisterDevice();

      new Notice("Connected to server.");
      this.isLoading = false;
      this.display();
    } catch (err: any) {
      this.isLoading = false;
      this.errorMessage = `Login error: ${err?.message || err}`;
      this.display();
    }
  }

  private async handleMultiAuthSubmit() {
    if (!this.usernameInput || !this.passwordInput) {
      this.errorMessage = "Please enter both username and password.";
      this.display();
      return;
    }

    this.isLoading = true;
    this.errorMessage = null;
    this.display();

    const cs = this.plugin.settings.cloudsync;
    try {
      const { authVerifier, encryptionKey } = await deriveZeroKnowledgeKeys(
        this.usernameInput,
        this.passwordInput
      );

      if (this.isRegisterMode) {
        const res = await requestUrl({
          url: `${cs.serverUrl}/api/auth/register`,
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            username: this.usernameInput,
            verifier: authVerifier,
          }),
          throw: false,
        });

        if (res.status !== 200 && res.status !== 201) {
          this.errorMessage = getResponseError(res, "Registration failed.");
          this.isLoading = false;
          this.display();
          return;
        }

        cs.token = res.json?.token;
        cs.userId = res.json?.user?.id || "";
        cs.username = this.usernameInput;
        cs.vaultId = this.app.vault.getName();
        cs.encryptionKey = encryptionKey;
        cs.has2FA = false;
        this.plugin.settings.password = encryptionKey;
        this.plugin.settings.encryptionMethod = "rclone-base64";

        await this.plugin.saveSettings();
        await this.plugin.autoRegisterDevice();

        this.isLoading = false;
        new Notice("Account created.");

        new TwoFactorModal(this.app, this.plugin, "intro", () => {
          this.display();
        }).open();
      } else {
        const res = await requestUrl({
          url: `${cs.serverUrl}/api/auth/login`,
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            username: this.usernameInput,
            verifier: authVerifier,
            totpCode: this.totpCodeInput || undefined,
          }),
          throw: false,
        });

        if (res.json?.requires2FA) {
          this.requires2FA = true;
          this.isLoading = false;
          this.errorMessage = null;
          this.display();
          return;
        }

        if (res.status !== 200) {
          this.errorMessage = getResponseError(res, "Invalid username or password.");
          this.isLoading = false;
          this.display();
          return;
        }

        cs.token = res.json.token;
        cs.userId = res.json.user?.id || "";
        cs.username = this.usernameInput;
        cs.vaultId = this.app.vault.getName();
        cs.encryptionKey = encryptionKey;
        this.plugin.settings.password = encryptionKey;
        this.plugin.settings.encryptionMethod = "rclone-base64";

        await this.plugin.saveSettings();
        await this.plugin.autoRegisterDevice();

        new Notice("Signed in.");
        this.isLoading = false;
        this.display();
      }
    } catch (err: any) {
      this.isLoading = false;
      this.errorMessage = `Authentication failed: ${err?.message || err}`;
      this.display();
    }
  }

  private async handleRecoverySubmit() {
    if (!this.usernameInput || !this.passwordInput) {
      this.errorMessage = "Please enter your username and new password.";
      this.display();
      return;
    }

    if (this.recoveryMethod === "totp" && (!this.totpCodeInput || this.totpCodeInput.length !== 6)) {
      this.errorMessage = "Please enter the 6-digit 2FA code from your authenticator app.";
      this.display();
      return;
    }

    if (this.recoveryMethod === "key" && !this.recoveryKeyInput) {
      this.errorMessage = "Please enter your recovery key.";
      this.display();
      return;
    }

    this.isLoading = true;
    this.errorMessage = null;
    this.display();

    const cs = this.plugin.settings.cloudsync;
    try {
      const { authVerifier, encryptionKey } = await deriveZeroKnowledgeKeys(
        this.usernameInput,
        this.passwordInput
      );

      const payload: Record<string, any> = {
        username: this.usernameInput,
        newVerifier: authVerifier,
      };

      if (this.recoveryMethod === "totp") {
        payload.totpCode = this.totpCodeInput;
      } else {
        payload.recoveryVerifier = await deriveRecoveryVerifier(this.recoveryKeyInput);
      }

      const res = await requestUrl({
        url: `${cs.serverUrl}/api/auth/recover`,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        throw: false,
      });

      if (res.status !== 200) {
        this.errorMessage = getResponseError(
          res,
          "Password reset failed. Please check your verification code."
        );
        this.isLoading = false;
        this.display();
        return;
      }

      cs.token = res.json?.token;
      cs.userId = res.json.user?.id || "";
      cs.username = this.usernameInput;
      cs.vaultId = this.app.vault.getName();
      cs.encryptionKey = encryptionKey;
      cs.has2FA = Boolean(res.json.has2FA !== undefined ? res.json.has2FA : true);
      this.plugin.settings.password = encryptionKey;
      this.plugin.settings.encryptionMethod = "rclone-base64";

      await this.plugin.saveSettings();
      await this.plugin.autoRegisterDevice();

      new Notice("Password updated. Signed in.");
      this.isLoading = false;
      this.isRecoveryMode = false;
      this.display();
    } catch (err: any) {
      this.isLoading = false;
      this.errorMessage = `Recovery failed: ${err?.message || err}`;
      this.display();
    }
  }

  private async renderLoggedInView(containerEl: HTMLElement) {
    const cs = this.plugin.settings.cloudsync;
    const vaultName = cs.vaultId || this.app.vault.getName();

    await this.fetchStorageUsage();

    if (cs.mode === "multi" && !cs.has2FA) {
      new Setting(containerEl)
        .setClass("banner-2fa")
        .setName("Two-factor authentication is not enabled")
        .setDesc("Protect your account from unauthorized access and enable verification.")
        .addButton((btn) => {
          btn
            .setButtonText("Set up 2FA")
            .setCta()
            .onClick(() => {
              new TwoFactorModal(this.app, this.plugin, "setup", (success) => {
                if (success) this.display();
              }).open();
            });
        });
    }

    // 1. Account & Server
    new Setting(containerEl)
      .setName("Account & Server")
      .setHeading();

    // 1. Unified Profile Info Card (Avatar, Name, Handle, Server, Edit & Logout)
    const profileCard = containerEl.createDiv({ cls: "profile-card" });
    const profileLeft = profileCard.createDiv({ cls: "profile-card-left" });

    const avatarWrapper = profileLeft.createDiv({ cls: "profile-card-avatar" });
    const effectiveName = cs.displayName || cs.username || (cs.mode === "single" ? "Personal Worker" : "User");
    const initial = (effectiveName || "U").charAt(0).toUpperCase();

    if (cs.serverUrl && cs.username) {
      const avatarImg = avatarWrapper.createEl("img", {
        attr: {
          src: `${cs.serverUrl}/api/user/avatar/${encodeURIComponent(cs.username)}?t=${Date.now()}`,
          alt: effectiveName,
        },
      });
      const fallbackSpan = avatarWrapper.createSpan({
        cls: "profile-card-avatar-fallback",
        text: initial,
      });
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
      avatarWrapper.createSpan({
        cls: "profile-card-avatar-fallback",
        text: initial,
      });
    }

    const profileInfo = profileLeft.createDiv({ cls: "profile-card-info" });
    profileInfo.createEl("div", {
      cls: "profile-card-name",
      text: effectiveName,
    });

    let serverHost = "";
    try {
      if (cs.serverUrl) serverHost = new URL(cs.serverUrl).host;
    } catch {}

    const metaParts = [];
    if (cs.username) metaParts.push(`@${cs.username}`);
    if (serverHost) metaParts.push(serverHost);

    profileInfo.createEl("div", {
      cls: "profile-card-meta",
      text: metaParts.join(" • "),
    });

    const profileActions = profileCard.createDiv({ cls: "profile-card-actions" });

    if (cs.username) {
      const editBtn = profileActions.createEl("button", {
        cls: "profile-card-btn",
        text: "Edit profile",
      });
      editBtn.onclick = () => {
        new EditProfileModal(this.app, this.plugin, () => this.display()).open();
      };
    }

    const logoutBtn = profileActions.createEl("button", {
      cls: "profile-card-btn mod-destructive",
      text: "Log out",
    });
    logoutBtn.onclick = async () => {
      if (!confirm("Are you sure you want to log out on this device?")) {
        return;
      }
      cs.token = "";
      cs.username = "";
      cs.displayName = "";
      cs.email = "";
      cs.encryptionKey = "";
      cs.vaultId = "";
      this.plugin.settings.password = "";
      await this.plugin.saveSettings();
      try {
        await destroyDBs();
      } catch (e) {
        console.warn("Logout db destroy skipped:", e);
      }
      new Notice("Logged out.");
      this.display();
    };

    if (this.storageUsedBytes !== null) {
      const mb = (this.storageUsedBytes / (1024 * 1024)).toFixed(2);
      const gbLimit = "10.00";
      const pct = (
        (this.storageUsedBytes / (10 * 1024 * 1024 * 1024)) *
        100
      ).toFixed(2);

      const storageSetting = new Setting(containerEl)
        .setName("Storage usage")
        .setDesc(`Using ${mb} MB of ${gbLimit} GB (${pct}%)`);

      const barTrack = storageSetting.controlEl.createDiv({
        cls: "storage-bar-track",
      });
      const barFill = barTrack.createDiv({ cls: "storage-bar-fill" });
      barFill.style.width = `${Math.min(100, Math.max(1, Number.parseFloat(pct)))}%`;
    }

    if (cs.mode === "multi") {
      new Setting(containerEl)
        .setName("Two-factor authentication")
        .setDesc(cs.has2FA ? "Enabled (Authenticator app)" : "Not enabled")
        .addExtraButton((btn) => {
          btn
            .setIcon("lucide-refresh-cw")
            .setTooltip("Refresh 2FA status from cloud")
            .onClick(async () => {
              btn.setDisabled(true);
              await this.fetchStorageUsage();
              new Notice(
                cs.has2FA
                  ? "2FA is enabled on this account."
                  : "2FA is not enabled on this account."
              );
              this.display();
            });
        })
        .addButton((btn) => {
          if (cs.has2FA) {
            btn.setButtonText("Disable").onClick(async () => {
              if (
                !confirm(
                  "Are you sure you want to disable two-factor authentication for your account?"
                )
              ) {
                return;
              }
              btn.setDisabled(true);
              btn.setButtonText("Disabling...");
              try {
                const res = await requestUrl({
                  url: `${cs.serverUrl}/api/user/disable-2fa`,
                  method: "POST",
                  headers: {
                    Authorization: `Bearer ${cs.token}`,
                    "Content-Type": "application/json",
                  },
                  body: JSON.stringify({}),
                  throw: false,
                });
                if (res.status === 200) {
                  cs.has2FA = false;
                  await this.plugin.saveSettings();
                  new Notice("Two-factor authentication disabled.");
                  this.display();
                } else {
                  btn.setDisabled(false);
                  btn.setButtonText("Disable");
                  new Notice("Failed to disable 2FA.");
                }
              } catch (err: any) {
                btn.setDisabled(false);
                btn.setButtonText("Disable");
                new Notice(`Error: ${err?.message || err}`);
              }
            });
          } else {
            btn
              .setButtonText("Set up")
              .setCta()
              .onClick(() => {
                new TwoFactorModal(this.app, this.plugin, "setup", (success) => {
                  if (success) this.display();
                }).open();
              });
          }
        });
    }

    // 2. Vault & Sync Controls
    new Setting(containerEl)
      .setName("Remote Vault & Sync Controls")
      .setHeading();

    const isSharedVault = !!(
      cs.vaultOwner &&
      cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase()
    );

    if (cs.vaultId) {
      const vaultSetting = new Setting(containerEl)
        .setName("Connected remote vault")
        .setDesc(
          isSharedVault
            ? `Currently syncing with shared vault "${cs.vaultId}" (owned by ${cs.vaultOwner}).`
            : `Currently syncing with remote vault "${cs.vaultId}".`
        )
        .addButton((btn) => {
          btn
            .setButtonText("Disconnect")
            .setClass("mod-destructive")
            .onClick(async () => {
              if (
                !confirm(
                  `Are you sure you want to disconnect from "${cs.vaultId}"?\n\nLocal files will remain intact, but syncing will stop until reconnected.`
                )
              ) {
                return;
              }
              const disconnectedVault = cs.vaultId;
              cs.vaultId = "";
              cs.vaultOwner = "";
              await this.plugin.saveSettings();
              new Notice(`Disconnected from remote vault "${disconnectedVault}".`);
              this.display();
            });
        })
        .addButton((btn) => {
          btn
            .setButtonText("Switch vault")
            .onClick(() => {
              new VaultPickerModal(this.app, this.plugin, () => this.display()).open();
            });
        });

      if (!isSharedVault) {
        vaultSetting.addButton((btn) => {
          btn
            .setButtonText("Collaborators")
            .onClick(() => {
              new VaultShareModal(this.app, this.plugin, cs.vaultId).open();
            });
        });
      }

      if (isSharedVault) {
        new Setting(containerEl)
          .setName("Shared vault encryption password")
          .setDesc(
            `If the owner encrypted this vault, enter the shared password to decrypt files. Leave empty if unencrypted.`
          )
          .addText((text) => {
            text
              .setPlaceholder("Enter shared vault password")
              .setValue(this.plugin.settings.password || "")
              .onChange(async (val) => {
                this.plugin.settings.password = val.trim();
                cs.encryptionKey = val.trim();
                await this.plugin.saveSettings();
              });
          });
      }
    } else {
      new Setting(containerEl)
        .setName("Connected remote vault")
        .setDesc("No remote vault connected. Choose an existing vault or create a new one.")
        .addButton((btn) => {
          btn
            .setButtonText("Choose vault")
            .setCta()
            .onClick(() => {
              new VaultPickerModal(this.app, this.plugin, () => this.display()).open();
            });
        });
    }

    const isPaused = this.plugin.settings.isSyncPaused ?? false;
    const hasVault = !!cs.vaultId;
    new Setting(containerEl)
      .setName("Sync status")
      .setDesc(
        !hasVault
          ? "Connect to a remote vault above to enable syncing."
          : isPaused
          ? "Sync is currently paused."
          : "Sync is active."
      )
      .addButton((btn) => {
        btn.setDisabled(!hasVault);
        if (isPaused) {
          btn
            .setButtonText("Resume")
            .setCta()
            .onClick(async () => {
              this.plugin.settings.isSyncPaused = false;
              await this.plugin.saveSettings();
              new Notice("Resumed sync.");
              this.display();
              this.plugin.syncRun("manual");
            });
        } else {
          btn
            .setButtonText("Pause")
            .onClick(async () => {
              this.plugin.settings.isSyncPaused = true;
              await this.plugin.saveSettings();
              new Notice("Paused sync.");
              this.display();
            });
        }
      })
      .addButton((btn) => {
        btn
          .setButtonText("Sync now")
          .setDisabled(!hasVault)
          .onClick(async () => {
            new Notice("Starting sync...");
            await this.plugin.syncRun("manual");
          });
      })
      .addButton((btn) => {
        btn
          .setButtonText("Dry run")
          .setDisabled(!hasVault)
          .onClick(async () => {
            new Notice("Simulating sync...");
            await this.plugin.syncRun("dry");
          });
      });

    new Setting(containerEl)
      .setName("Auto-sync interval")
      .setDesc("Frequency of background sync checks")
      .addDropdown((drop) => {
        drop
          .addOption("-1", "Manual only")
          .addOption("60000", "Every 1 minute")
          .addOption("300000", "Every 5 minutes")
          .addOption("900000", "Every 15 minutes")
          .addOption("1800000", "Every 30 minutes")
          .setValue(
            `${this.plugin.settings.autoRunEveryMilliseconds ?? 300000}`
          )
          .onChange(async (val) => {
            this.plugin.settings.autoRunEveryMilliseconds = Number.parseInt(val, 10);
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync on startup")
      .setDesc("Run sync automatically when Obsidian launches")
      .addToggle((toggle) => {
        toggle
          .setValue((this.plugin.settings.initRunAfterMilliseconds ?? -1) > 0)
          .onChange(async (val) => {
            this.plugin.settings.initRunAfterMilliseconds = val ? 2000 : -1;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync on file save")
      .setDesc("Trigger sync shortly after making edits")
      .addToggle((toggle) => {
        toggle
          .setValue((this.plugin.settings.syncOnSaveAfterMilliseconds ?? -1) > 0)
          .onChange(async (val) => {
            this.plugin.settings.syncOnSaveAfterMilliseconds = val ? 3000 : -1;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Show sync notifications")
      .setDesc("Display brief status notices when files are synced")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.showSyncNotifications ?? false)
          .onChange(async (val) => {
            this.plugin.settings.showSyncNotifications = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Conflict resolution")
      .setDesc("Strategy when notes are independently modified on multiple devices")
      .addDropdown((drop) => {
        drop
          .addOption("keep_newer", "Keep newer version")
          .addOption("keep_larger", "Keep larger version")
          .setValue(
            this.plugin.settings.conflictAction === "keep_larger"
              ? "keep_larger"
              : "keep_newer"
          )
          .onChange(async (val: any) => {
            this.plugin.settings.conflictAction = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Deletion safety threshold")
      .setDesc("Prevent syncing if too many files are deleted at once")
      .addDropdown((drop) => {
        drop
          .addOption("0", "Disabled")
          .addOption("10", "10 files")
          .addOption("25", "25 files")
          .addOption("50", "50 files")
          .setValue(
            `${this.plugin.settings.safetyDeletionThreshold ?? 25}`
          )
          .onChange(async (val) => {
            this.plugin.settings.safetyDeletionThreshold = Number.parseInt(val, 10);
            await this.plugin.saveSettings();
          });
      });

    // 3. File Types & Filters
    new Setting(containerEl)
      .setName("File Inclusions & Filters")
      .setHeading();

    const ignoredFolders = this.plugin.settings.ignorePaths || [];
    const excludedDescFrag = createFragment((f) => {
      f.appendText("Paths that will be skipped during synchronization.");
      if (ignoredFolders.length > 0) {
        f.appendText(" Currently excluded:");
        const ul = f.createEl("ul");
        for (const folder of ignoredFolders) {
          ul.createEl("li", { text: folder });
        }
      }
    });

    new Setting(containerEl)
      .setName("Excluded folders")
      .setDesc(excludedDescFrag)
      .addButton((btn) => {
        btn
          .setButtonText("Manage exclusions")
          .onClick(() => {
            new ExcludedFoldersModal(this.app, this.plugin).open();
          });
      });

    new Setting(containerEl)
      .setName("Include image files")
      .setDesc("Sync png, jpg, jpeg, gif, svg, webp, and bmp images")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncImages ?? true)
          .onChange(async (val) => {
            this.plugin.settings.syncImages = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Include audio files")
      .setDesc("Sync mp3, wav, m4a, 3gp, flac, ogg, and opus audio")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncAudio ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncAudio = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Include video files")
      .setDesc("Sync mp4, webm, mov, and mkv video recordings")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncVideos ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncVideos = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Include PDF documents")
      .setDesc("Sync PDF document files")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncPdfs ?? true)
          .onChange(async (val) => {
            this.plugin.settings.syncPdfs = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Include other attachments")
      .setDesc("Sync any other non-markdown attachment formats")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncUnsupported ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncUnsupported = val;
            await this.plugin.saveSettings();
          });
      });

    // 4. Device Configuration Backups
    new Setting(containerEl)
      .setName("Device Configuration Backups")
      .setHeading();

    initDeviceIdentity(this.plugin.settings);
    new Setting(containerEl)
      .setName("Device name")
      .setDesc("Identifies this device in activity logs and configuration backups")
      .addText((text) => {
        text
          .setPlaceholder(this.plugin.settings.deviceName || "My Device")
          .setValue(this.plugin.settings.deviceName ?? "")
          .onChange(async (val) => {
            const name = val.trim() || "My Device";
            this.plugin.settings.deviceName = name;
            await this.plugin.saveSettings();
            const { fsRemote } = this.plugin.getOrCreateClients();
            if (
              fsRemote &&
              typeof (fsRemote as any).registerDevice === "function"
            ) {
              await (fsRemote as any).registerDevice({
                deviceId: this.plugin.settings.deviceId!,
                deviceName: this.plugin.settings.deviceName,
                platform: Platform.isMobile ? "mobile" : "desktop",
                lastBackup: this.plugin.settings.lastSettingsBackupTime,
              });
            }
          });
      });

    const thisDeviceSetting = new Setting(containerEl)
      .setName(`${this.plugin.settings.deviceName || "My Device"} (This device)`)
      .setDesc(
        this.plugin.settings.lastSettingsBackupTime
          ? `Last backed up: ${new Date(
              this.plugin.settings.lastSettingsBackupTime
            ).toLocaleString()}`
          : "Never backed up to cloud"
      )
      .addButton((btn) => {
        btn
          .setButtonText("Backup now")
          .setCta()
          .onClick(async () => {
            btn.setDisabled(true);
            btn.setButtonText("Backing up...");
            const { fsEncrypt, fsRemote } = this.plugin.getOrCreateClients();
            try {
              const res = await backupDeviceSettings(
                this.app,
                fsEncrypt,
                fsRemote as FakeFsWorker,
                this.plugin.settings,
                (msg) => {
                  thisDeviceSetting.setDesc(msg);
                }
              );
              await this.plugin.saveSettings();
              thisDeviceSetting.setDesc(
                `Last backed up: ${new Date(res.timestamp).toLocaleString()} (${
                  res.fileCount
                } files)`
              );
              new Notice(`Backed up ${res.fileCount} settings files.`);
              btn.setButtonText("Backed up!");
              window.setTimeout(() => {
                btn.setDisabled(false);
                btn.setButtonText("Backup now");
              }, 2000);
            } catch (err: any) {
              btn.setDisabled(false);
              btn.setButtonText("Backup now");
              new Notice(`Failed to back up settings: ${err?.message || err}`);
            }
          });
      });

    const otherDevicesContainer = containerEl.createDiv();
    new Setting(otherDevicesContainer)
      .setName("Loading other devices...")
      .setDesc("Fetching connected devices from cloud");

    const { fsRemote, fsEncrypt } = this.plugin.getOrCreateClients();
    if (fsRemote && typeof (fsRemote as any).getDevices === "function") {
      const workerClient = fsRemote as FakeFsWorker;
      this.plugin.autoRegisterDevice().catch(() => {});

      const timeoutPromise = new Promise<DeviceInfo[]>((_, reject) =>
        setTimeout(() => reject(new Error("Request timed out")), 8000)
      );

      Promise.race([workerClient.getDevices(), timeoutPromise])
        .then((devices) => {
          otherDevicesContainer.empty();
          const other = devices.filter(
            (d) => d.deviceId !== this.plugin.settings.deviceId
          );
          if (other.length === 0) {
            new Setting(otherDevicesContainer)
              .setName("No other device backups found")
              .setDesc(
                "Backups created on your other devices will appear here."
              );
            return;
          }

          for (const dev of other) {
            const hasBackup = Boolean(dev.lastBackup);
            const timeStr = dev.lastBackup
              ? new Date(dev.lastBackup).toLocaleString()
              : "Never";

            new Setting(otherDevicesContainer)
              .setName(dev.deviceName || "Unnamed Device")
              .setDesc(
                hasBackup
                  ? `Last backup: ${timeStr} • ${dev.fileCount || 0} config files`
                  : `Last active: ${new Date(dev.lastActive).toLocaleString()} • No backup`
              )
              .addButton((restoreBtn) => {
                restoreBtn
                  .setButtonText("Restore to this device")
                  .setDisabled(!hasBackup)
                  .onClick(async () => {
                    if (
                      !confirm(
                        `Restore settings from "${dev.deviceName}" to this device?\n\nThis will update your local themes, snippets, and plugin configurations.`
                      )
                    ) {
                      return;
                    }
                    restoreBtn.setDisabled(true);
                    restoreBtn.setButtonText("Restoring...");
                    try {
                      const res = await restoreDeviceSettings(
                        this.app,
                        fsEncrypt,
                        dev.deviceId,
                        (msg) => new Notice(msg, 1500)
                      );
                      restoreBtn.setButtonText("Restored!");
                      new Notice(
                        `Restored ${res.restoredCount} configuration files. Reload Obsidian to apply changes.`,
                        6000
                      );
                      window.setTimeout(() => {
                        restoreBtn.setDisabled(false);
                        restoreBtn.setButtonText("Restore to this device");
                      }, 3000);
                    } catch (err: any) {
                      restoreBtn.setDisabled(false);
                      restoreBtn.setButtonText("Restore to this device");
                      new Notice(
                        `Failed to restore settings: ${
                          err?.message || err
                        }`
                      );
                    }
                  });
              });
          }
        })
        .catch((err) => {
          console.error("CloudSync: Failed to load devices:", err);
          otherDevicesContainer.empty();
          new Setting(otherDevicesContainer)
            .setName("Could not load other devices")
            .setDesc("Check your network connection and click Refresh above.");
        });
    } else {
      otherDevicesContainer.empty();
      new Setting(otherDevicesContainer)
        .setName("Other devices")
        .setDesc("Device backups will be available once connected to CloudSync.");
    }

    // 5. History & Recovery Tools
    new Setting(containerEl)
      .setName("History & Recovery Tools")
      .setHeading();

    new Setting(containerEl)
      .setName("Deleted files (Trash)")
      .setDesc("Recover files deleted from your vault within the last 30 days")
      .addButton((btn) => {
        btn
          .setButtonText("Browse trash")
          .onClick(() => {
            new DeletedFilesModal(this.app, this.plugin, false).open();
          });
      })
      .addButton((btn) => {
        btn
          .setButtonText("Bulk restore")
          .onClick(() => {
            new DeletedFilesModal(this.app, this.plugin, true).open();
          });
      });

    new Setting(containerEl)
      .setName("Sync activity log")
      .setDesc("Inspect detailed sync operations and network logs for troubleshooting")
      .addButton((btn) => {
        btn
          .setButtonText("Open log")
          .onClick(() => {
            new SyncLogModal(this.app, this.plugin).open();
          });
      });
  }

  private async fetchStorageUsage() {
    const cs = this.plugin.settings.cloudsync;
    if (!cs.serverUrl || !cs.token) return;

    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/user/me`,
        method: "GET",
        headers: { Authorization: `Bearer ${cs.token}` },
        throw: false,
      });

      if (res.status === 200) {
        if (res.json?.storageUsedBytes !== undefined) {
          this.storageUsedBytes = res.json.storageUsedBytes;
        }
        if (res.json?.has2FA !== undefined && cs.has2FA !== res.json.has2FA) {
          cs.has2FA = res.json.has2FA;
          await this.plugin.saveSettings();
        }
        if (res.json?.hasAvatar !== undefined && cs.hasAvatar !== res.json.hasAvatar) {
          cs.hasAvatar = res.json.hasAvatar;
          await this.plugin.saveSettings();
        }
        if (res.json?.displayName !== undefined && cs.displayName !== res.json.displayName) {
          cs.displayName = res.json.displayName;
          await this.plugin.saveSettings();
        }
      }
    } catch {
      // Ignore background storage check failure
    }
  }
}
