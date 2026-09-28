import {
  type App,
  Notice,
  Platform,
  PluginSettingTab,
  Setting,
  requestUrl,
} from "obsidian";
import { OBSIDIAN_LOGO_PNG } from "./assets/logo";
import { generateRecoveryKey } from "./authHelper";
import {
  type CloudSyncConfig,
  DEFAULT_CLOUDSYNC_CONFIG,
  type RemotelySavePluginSettings,
} from "./baseTypes";
import { ChangePasswordModal } from "./changePasswordModal";
import { hexEncode } from "./cryptoV2";
import { DeletedFilesModal } from "./deletedFilesModal";
import {
  backupDeviceSettings,
  initDeviceIdentity,
  restoreDeviceSettings,
} from "./deviceSettings";
import { EditProfileModal } from "./editProfileModal";
import { ExcludedFoldersModal } from "./excludedFoldersModal";
import type { DeviceInfo, FakeFsWorker } from "./fsWorker";
import { destroyDBs } from "./localdb";
import type CloudSyncPlugin from "./main";
import { normalizeServerUrl } from "./misc";
import { createOtpInput } from "./otpInput";
import { RecoveryKeyModal } from "./recoveryKeyModal";
import { confirmVaultRekey, runVaultRekey } from "./rotationUi";
import { SyncLogModal } from "./syncLogModal";
import { TwoFactorModal } from "./twoFactorModal";
import { VaultPickerModal } from "./vaultPickerModal";
import { cancelVaultRotation, isVaultRotationRunning } from "./vaultRotation";
import { VaultShareModal } from "./vaultShareModal";

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
      !cs.sessionExpired &&
      Boolean(cs.username || cs.email || cs.userId === "default");

    if (!isConfigured) {
      containerEl.addClass("is-auth-active");
      this.renderServerUrlView(containerEl);
    } else if (!isAuthenticated) {
      containerEl.addClass("is-auth-active");
      if (cs.sessionExpired && !this.errorMessage) {
        this.errorMessage = "Your session expired. Please sign in again.";
      }
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
      placeholder: "cloudsync.example.workers.dev (https:// optional)",
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
    const url = normalizeServerUrl(this.serverUrlInput);
    if (!url) {
      this.errorMessage =
        "Please enter a valid server address, e.g. cloudsync.example.workers.dev";
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
      await this.plugin.keyManager.loginSingle({
        password: this.passwordInput,
      });
      cs.sessionExpired = false;
      this.errorMessage = null;
      cs.userId = "default";
      cs.username = "Owner";
      cs.vaultId = this.app.vault.getName();
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
      if (this.isRegisterMode) {
        const { recoveryKey } = await this.plugin.keyManager.register({
          username: this.usernameInput,
          password: this.passwordInput,
        });
        cs.vaultId = this.app.vault.getName();
        cs.has2FA = false;
        this.plugin.settings.encryptionMethod = "rclone-base64";
        await this.plugin.saveSettings();
        await this.plugin.autoRegisterDevice();

        this.isLoading = false;
        this.errorMessage = null;
        new Notice("Account created.");
        new RecoveryKeyModal(this.app, recoveryKey, () =>
          this.display()
        ).open();
        new TwoFactorModal(this.app, this.plugin, "intro", () => {
          this.display();
        }).open();
        return;
      }

      const result = await this.plugin.keyManager.login({
        username: this.usernameInput,
        password: this.passwordInput,
        totpCode: this.totpCodeInput || undefined,
      });
      if ("requires2FA" in result && result.requires2FA) {
        this.requires2FA = true;
        this.isLoading = false;
        this.errorMessage = null;
        this.display();
        return;
      }
      if ("legacy" in result && result.legacy) {
        this.isLoading = false;
        this.errorMessage =
          "This account was created with an older version of CloudSync. Please register a new account.";
        this.display();
        return;
      }

      cs.vaultId = this.app.vault.getName();
      this.plugin.settings.encryptionMethod = "rclone-base64";
      await this.plugin.saveSettings();
      await this.plugin.autoRegisterDevice();

      new Notice("Signed in.");
      this.isLoading = false;
      this.display();
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

    if (
      this.recoveryMethod === "totp" &&
      (!this.totpCodeInput || this.totpCodeInput.length !== 6)
    ) {
      this.errorMessage =
        "Please enter the 6-digit 2FA code from your authenticator app.";
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
      const scheme = await this.plugin.keyManager.accountScheme(
        this.usernameInput
      );
      if (scheme !== 2) {
        this.isLoading = false;
        this.errorMessage =
          "This account was created with an older version of CloudSync. Please register a new account.";
        this.display();
        return;
      }
      if (this.recoveryMethod === "key") {
        if (
          !confirm(
            "Reset your password with the recovery key?\n\nYour notes stay readable: the recovery key unlocks your vault keys."
          )
        ) {
          this.isLoading = false;
          this.display();
          return;
        }
        await this.plugin.keyManager.recoverWithRecoveryKey({
          username: this.usernameInput,
          recoveryKey: this.recoveryKeyInput,
          newPassword: this.passwordInput,
        });
      } else {
        if (
          !confirm(
            "Reset your password with a 2FA code?\n\nWARNING: this cannot restore your vault keys. Existing encrypted notes will be permanently unreadable.\n\nOnly continue if you have lost the recovery key."
          )
        ) {
          this.isLoading = false;
          this.display();
          return;
        }
        await this.plugin.keyManager.recoverWithTotp({
          username: this.usernameInput,
          totpCode: this.totpCodeInput,
          newPassword: this.passwordInput,
        });
      }
      cs.vaultId = this.app.vault.getName();
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
    if (this.plugin.settings.cloudsync.sessionExpired) {
      // fetchStorageUsage detected a 401 and queued an auth-view refresh.
      return;
    }

    await this.renderRotationBanner(containerEl);

    if (this.plugin.settings.encryptionMethod === "openssl-base64") {
      new Setting(containerEl)
        .setClass("banner-2fa")
        .setName("Legacy encryption mode detected")
        .setDesc(
          "This vault uses the legacy OpenSSL AES-CBC format, which does not authenticate note contents. A malicious server could alter notes without detection. New accounts use rclone encryption; migrate by re-encrypting with a fresh vault to get integrity protection."
        );
    }

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

    // 1. Unified Profile Info Card (Native Obsidian Setting)
    const effectiveName = cs.displayName || cs.username || (cs.mode === "single" ? "Personal Worker" : "User");
    const initial = (effectiveName || "U").charAt(0).toUpperCase();

    let serverHost = "";
    try {
      if (cs.serverUrl) serverHost = new URL(cs.serverUrl).host;
    } catch {}

    const metaParts: string[] = [];
    if (cs.username) metaParts.push(`@${cs.username}`);
    if (serverHost) metaParts.push(serverHost);

    const profileSetting = new Setting(containerEl)
      .setName(effectiveName)
      .setDesc(metaParts.join(" • "));

    profileSetting.settingEl.addClass("profile-setting-item");

    const avatarWrapper = profileSetting.infoEl.createDiv({ cls: "profile-setting-avatar" });
    if (cs.serverUrl && cs.username) {
      const avatarImg = avatarWrapper.createEl("img", {
        attr: {
          src: `${cs.serverUrl}/api/user/avatar/${encodeURIComponent(cs.username)}?t=${Date.now()}`,
          alt: effectiveName,
        },
      });
      const fallbackSpan = avatarWrapper.createSpan({
        cls: "profile-setting-avatar-fallback",
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
        cls: "profile-setting-avatar-fallback",
        text: initial,
      });
    }

    const detailsWrapper = profileSetting.infoEl.createDiv({ cls: "profile-setting-details" });
    detailsWrapper.appendChild(profileSetting.nameEl);
    detailsWrapper.appendChild(profileSetting.descEl);

    profileSetting.infoEl.addClass("profile-setting-info");
    profileSetting.infoEl.prepend(avatarWrapper);

    if (cs.username) {
      profileSetting.addButton((btn) => {
        btn
          .setButtonText("Edit profile")
          .onClick(() => {
            new EditProfileModal(this.app, this.plugin, () => this.display()).open();
          });
      });
    }

    profileSetting.addButton((btn) => {
      btn
        .setButtonText("Log out")
        .setClass("mod-warning")
        .onClick(async () => {
          if (!confirm("Are you sure you want to log out on this device?")) {
            return;
          }
          await this.plugin.keyManager.logout();
          cs.vaultId = "";
          cs.vaultOwner = "";
          this.plugin.clearCachedClients();
          await this.plugin.saveSettings();
          try {
            await destroyDBs();
          } catch (e) {
            console.warn("Logout db destroy skipped:", e);
          }
          new Notice("Logged out.");
          this.display();
        });
    });

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

    if (cs.mode === "multi" && cs.username) {
      new Setting(containerEl)
        .setName("Recovery key")
        .setDesc(
          cs.recoveryKey
            ? "Stored on this device. Keep it offline; anyone with it can reset your password."
            : "No recovery key stored on this device. Generate one so you can reset your password without your authenticator app."
        )
        .addExtraButton((btn) => {
          btn
            .setIcon("lucide-copy")
            .setTooltip("Copy recovery key")
            .setDisabled(!cs.recoveryKey)
            .onClick(async () => {
              if (!cs.recoveryKey) return;
              await navigator.clipboard.writeText(cs.recoveryKey);
              new Notice("Recovery key copied to clipboard.");
            });
        })
        .addButton((btn) => {
          btn.setButtonText("View").onClick(() => {
            if (!cs.recoveryKey) {
              new Notice("No recovery key stored on this device.");
              return;
            }
            new RecoveryKeyModal(this.app, cs.recoveryKey).open();
          });
        })
        .addButton((btn) => {
          btn
            .setButtonText(cs.recoveryKey ? "Generate new" : "Generate")
            .setCta()
            .onClick(async () => {
              if (
                cs.recoveryKey &&
                !confirm(
                  "Generating a new recovery key invalidates the previous one. Continue?"
                )
              ) {
                return;
              }
              btn.setDisabled(true);
              try {
                const newKey = generateRecoveryKey();
                await this.plugin.keyManager.enableRecoveryKey(newKey);
                new RecoveryKeyModal(this.app, newKey, () =>
                  this.display()
                ).open();
              } catch (err: any) {
                new Notice(`Error: ${err?.message || err}`);
                btn.setDisabled(false);
              }
            });
        });

      new Setting(containerEl)
        .setName("Password")
        .setDesc(
          "Change your account password. Vault keys are re-wrapped, so your notes stay readable."
        )
        .addButton((btn) => {
          btn.setButtonText("Change password").onClick(() => {
            new ChangePasswordModal(this.app, this.plugin, () =>
              this.display()
            ).open();
          });
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
              this.plugin.clearCachedClients();
              await this.plugin.saveSettings();
              new Notice(
                `Disconnected from remote vault "${disconnectedVault}".`
              );
              this.display();
            });
        })
        .addButton((btn) => {
          btn.setButtonText("Switch vault").onClick(() => {
            new VaultPickerModal(this.app, this.plugin, () =>
              this.display()
            ).open();
          });
        });

      if (!isSharedVault) {
        vaultSetting.addButton((btn) => {
          btn.setButtonText("Collaborators").onClick(() => {
            new VaultShareModal(this.app, this.plugin, cs.vaultId).open();
          });
        });
      }

      if (isSharedVault) {
        new Setting(containerEl)
          .setName("Shared vault key")
          .setDesc(
            "This vault's key was delivered automatically by the owner. No password needs to be entered."
          );
      }
    } else {
      new Setting(containerEl)
        .setName("Connected remote vault")
        .setDesc(
          "No remote vault connected. Choose an existing vault or create a new one."
        )
        .addButton((btn) => {
          btn
            .setButtonText("Choose vault")
            .setCta()
            .onClick(() => {
              new VaultPickerModal(this.app, this.plugin, () =>
                this.display()
              ).open();
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
            const { fsRemote } = await this.plugin.getOrCreateClients();
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
            const { fsEncrypt, fsRemote } =
              await this.plugin.getOrCreateClients();
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

    const { fsRemote, fsEncrypt } = await this.plugin.getOrCreateClients();
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
        .setDesc(
          "Device backups will be available once connected to CloudSync."
        );
    }

    // 5. History & Recovery Tools
    new Setting(containerEl).setName("History & Recovery Tools").setHeading();

    new Setting(containerEl)
      .setName("Deleted files (Trash)")
      .setDesc("Recover files deleted from your vault within the last 30 days")
      .addButton((btn) => {
        btn.setButtonText("Browse trash").onClick(() => {
          new DeletedFilesModal(this.app, this.plugin, false).open();
        });
      })
      .addButton((btn) => {
        btn.setButtonText("Bulk restore").onClick(() => {
          new DeletedFilesModal(this.app, this.plugin, true).open();
        });
      });

    new Setting(containerEl)
      .setName("Sync activity log")
      .setDesc(
        "Inspect detailed sync operations and network logs for troubleshooting"
      )
      .addButton((btn) => {
        btn.setButtonText("Open log").onClick(() => {
          new SyncLogModal(this.app, this.plugin).open();
        });
      });

    if (!isSharedVault && cs.scheme === 2) {
      new Setting(containerEl).setName("Advanced").setHeading();

      new Setting(containerEl)
        .setName("Re-key vault key")
        .setDesc(
          "Generate a new random vault key and re-encrypt every file. Use it to invalidate a key that someone else may have seen."
        )
        .addButton((btn) => {
          btn
            .setButtonText("Re-key vault")
            .setWarning()
            .onClick(async () => {
              if (!cs.vaultId || !confirmVaultRekey()) return;
              if (this.plugin.isSyncing || this.plugin.isFastSyncing) {
                new Notice(
                  "Wait for the current sync to finish before re-keying."
                );
                return;
              }
              if (isVaultRotationRunning(this.plugin, cs.vaultId)) {
                new Notice(
                  "A re-key is already running on this device. See the banner above for progress."
                );
                return;
              }
              await runVaultRekey(this.plugin, cs.vaultId);
              this.display();
            });
        });

      new Setting(containerEl)
        .setName("Reset local sync database")
        .setDesc(
          "Forgets the local record of what was synced so the next sync compares local and remote from scratch. Use it when a sync reports mass modifications after switching accounts or vaults. Nothing is deleted from disk or cloud."
        )
        .addButton((btn) => {
          btn
            .setButtonText("Reset")
            .setWarning()
            .onClick(async () => {
              if (
                !confirm(
                  "Reset the local sync database? The next sync will compare everything fresh. Nothing is deleted from disk or cloud."
                )
              ) {
                return;
              }
              await this.plugin.resetLocalSyncState();
              this.display();
            });
        });

      new Setting(containerEl)
        .setName("Write re-key debug log")
        .setDesc(
          "Append every re-key step to rotation-debug.log in the plugin folder, for troubleshooting long or interrupted re-keys."
        )
        .addToggle((toggle) =>
          toggle
            .setValue(this.plugin.settings.debugRotationLog ?? true)
            .onChange(async (value) => {
              this.plugin.settings.debugRotationLog = value;
              await this.plugin.saveSettings();
            })
        );

      new Setting(containerEl)
        .setName("Export vault encryption key")
        .setDesc(
          "Only needed to decrypt an offline copy of this vault (for example with rclone) or to recover if the server ever loses your key material. Sharing a vault never needs this."
        )
        .addButton((btn) => {
          btn
            .setButtonText("Copy vault key")
            .setWarning()
            .onClick(async () => {
              const vaultKey = cs.vaultId
                ? await this.plugin.keyManager.getVaultKey(cs.vaultId)
                : null;
              if (!vaultKey) {
                new Notice("This vault has no encryption key to export yet.");
                return;
              }
              await navigator.clipboard.writeText(hexEncode(vaultKey));
              new Notice(
                "Vault key copied. Anyone with it and a copy of the encrypted vault can read everything in it. Store it offline and never share it for collaboration.",
                12000
              );
            });
        });
    }
  }

  private async renderRotationBanner(containerEl: HTMLElement) {
    const cs = this.plugin.settings.cloudsync;
    if (cs.scheme !== 2 || !cs.vaultId || !cs.serverUrl || !cs.token) return;
    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/vaults`,
        headers: { Authorization: `Bearer ${cs.token}` },
        throw: false,
      });
      if (res.status !== 200 || !Array.isArray(res.json?.vaults)) return;
      const vault = res.json.vaults.find(
        (v: any) => v.name === cs.vaultId && !v.isShared
      );
      if (!vault?.rotating) return;

      const ownedByThisDevice =
        !vault.rotatingBy || vault.rotatingBy === this.plugin.settings.deviceId;
      const progress = cs.lastRotationProgress;
      const progressLine = progress
        ? `\n\nProgress: ${progress.message} (updated ${new Date(
            progress.updatedAt
          ).toLocaleTimeString()})`
        : "";
      const banner = new Setting(containerEl)
        .setClass("banner-2fa")
        .setName(
          ownedByThisDevice
            ? "Vault re-key needs finishing"
            : "Vault re-key is running elsewhere"
        )
        .setDesc(
          ownedByThisDevice
            ? `Sync is paused for this vault. Finish the re-key to restore syncing, or cancel to keep the previous key.${progressLine}${
                cs.lastRotationError
                  ? `\n\nLast error: ${cs.lastRotationError}`
                  : ""
              }`
            : "Another device is re-keying this vault. Wait for it to finish; sync resumes automatically."
        );
      if (!ownedByThisDevice) return;

      banner
        .addButton((btn) => {
          btn
            .setButtonText("Retry re-key")
            .setCta()
            .onClick(async () => {
              await runVaultRekey(this.plugin, cs.vaultId);
              this.display();
            });
        })
        .addButton((btn) => {
          btn.setButtonText("Cancel rotation").onClick(async () => {
            try {
              await cancelVaultRotation(this.plugin, cs.vaultId);
              cs.lastRotationError = undefined;
              cs.lastRotationProgress = undefined;
              await this.plugin.saveSettings();
              new Notice(
                "Rotation canceled. The previous vault key is still in use."
              );
            } catch (err: any) {
              new Notice(`Failed to cancel: ${err?.message || err}`);
            }
            this.display();
          });
        });
    } catch {}
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
      } else if (res.status === 401) {
        await this.plugin.markSessionExpired();
      }
    } catch {
      // Ignore background storage check failure
    }
  }
}
