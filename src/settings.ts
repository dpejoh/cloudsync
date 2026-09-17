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
import { destroyDBs } from "./localdb";
import type CloudSyncPlugin from "./main";

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
    containerEl.addClass("cloudsync-settings-page");

    const cs = this.plugin.settings.cloudsync;
    const isConfigured = Boolean(cs.serverUrl);
    const isAuthenticated =
      Boolean(cs.token) &&
      Boolean(cs.username || cs.email || cs.userId === "default");

    if (!isConfigured) {
      containerEl.addClass("cloudsync-auth-active");
      this.renderServerUrlPrompt(containerEl);
    } else if (!isAuthenticated) {
      containerEl.addClass("cloudsync-auth-active");
      this.renderAuthPrompt(containerEl);
    } else {
      containerEl.removeClass("cloudsync-auth-active");
      await this.renderLoggedInView(containerEl);
    }
  }

  hide(): void {
    super.hide();
    this.containerEl.removeClass("cloudsync-auth-active");
    this.containerEl.removeClass("cloudsync-settings-page");
  }

  private renderServerUrlPrompt(containerEl: HTMLElement) {
    const authWrapper = containerEl.createDiv({ cls: "cloudsync-auth-wrapper" });
    const authBox = authWrapper.createDiv({ cls: "cloudsync-auth-box" });

    const logoEl = authBox.createDiv({ cls: "cloudsync-auth-logo" });
    logoEl.createEl("img", {
      cls: "cloudsync-logo-img",
      attr: { src: OBSIDIAN_LOGO_PNG, alt: "Obsidian" },
    });

    authBox.createDiv({
      cls: "cloudsync-auth-title",
      text: "Connect to CloudSync",
    });
    authBox.createDiv({
      cls: "cloudsync-auth-subtitle",
      text: "Enter your Cloudflare Worker or Private VPS server URL to begin.",
    });

    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "cloudsync-error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "cloudsync-auth-form" });

    const urlGroup = form.createDiv({ cls: "cloudsync-input-group" });
    urlGroup.createEl("label", {
      text: "Sync Server URL",
      cls: "cloudsync-input-label",
    });
    const urlInputEl = urlGroup.createEl("input", {
      type: "url",
      cls: "cloudsync-text-input",
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
      cls: "mod-cta cloudsync-primary-btn",
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

  private renderAuthPrompt(containerEl: HTMLElement) {
    const cs = this.plugin.settings.cloudsync;
    const isSingleMode = cs.mode === "single";

    const authWrapper = containerEl.createDiv({ cls: "cloudsync-auth-wrapper" });
    const authBox = authWrapper.createDiv({ cls: "cloudsync-auth-box" });

    const logoEl = authBox.createDiv({ cls: "cloudsync-auth-logo" });
    logoEl.createEl("img", {
      cls: "cloudsync-logo-img",
      attr: { src: OBSIDIAN_LOGO_PNG, alt: "Obsidian" },
    });

    if (isSingleMode) {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Unlock CloudSync",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: `Server: ${cs.serverUrl}`,
      });
    } else if (this.isRecoveryMode) {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Reset your password",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text:
          this.recoveryMethod === "totp"
            ? "Enter your username, 2FA code from your authenticator app, and new password."
            : "Enter your username and recovery key to set a new password.",
      });
    } else if (this.isRegisterMode) {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Create an account",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: `Server: ${cs.serverUrl}`,
      });
    } else {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Sign in to CloudSync",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: `Server: ${cs.serverUrl}`,
      });
    }

    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "cloudsync-error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "cloudsync-auth-form" });

    if (isSingleMode) {
      const passwordGroup = form.createDiv({ cls: "cloudsync-input-group" });
      passwordGroup.createEl("label", {
        text: "Master Password",
        cls: "cloudsync-input-label",
      });
      const passwordInputEl = passwordGroup.createEl("input", {
        type: "password",
        cls: "cloudsync-text-input",
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
        cls: "mod-cta cloudsync-primary-btn",
        text: this.isLoading ? "Unlocking..." : "Connect & Sync",
      });
      unlockBtn.disabled = this.isLoading;
      unlockBtn.onclick = () => this.handleSingleLogin();
    } else if (this.isRecoveryMode) {
      const userGroup = form.createDiv({ cls: "cloudsync-input-group" });
      userGroup.createEl("label", { text: "Username", cls: "cloudsync-input-label" });
      const userInputEl = userGroup.createEl("input", {
        type: "text",
        cls: "cloudsync-text-input",
        value: this.usernameInput,
        placeholder: "username",
      });
      userInputEl.oninput = (e) => {
        this.usernameInput = (e.target as HTMLInputElement).value.trim();
        this.errorMessage = null;
      };

      if (this.recoveryMethod === "totp") {
        const totpGroup = form.createDiv({ cls: "cloudsync-input-group" });
        totpGroup.createEl("label", {
          text: "2FA Verification Code",
          cls: "cloudsync-input-label",
        });
        const totpInputEl = totpGroup.createEl("input", {
          type: "text",
          cls: "cloudsync-text-input",
          value: this.totpCodeInput,
          placeholder: "6-digit code",
        });
        totpInputEl.maxLength = 6;
        totpInputEl.oninput = (e) => {
          this.totpCodeInput = (e.target as HTMLInputElement).value.trim();
          this.errorMessage = null;
        };
      } else {
        const recGroup = form.createDiv({ cls: "cloudsync-input-group" });
        recGroup.createEl("label", {
          text: "Recovery Key",
          cls: "cloudsync-input-label",
        });
        const recInputEl = recGroup.createEl("input", {
          type: "text",
          cls: "cloudsync-text-input",
          value: this.recoveryKeyInput,
          placeholder: "SYNC-XXXX-XXXX-XXXX-XXXX",
        });
        recInputEl.oninput = (e) => {
          this.recoveryKeyInput = (e.target as HTMLInputElement).value.trim();
          this.errorMessage = null;
        };
      }

      const newPassGroup = form.createDiv({ cls: "cloudsync-input-group" });
      newPassGroup.createEl("label", {
        text: "New Password",
        cls: "cloudsync-input-label",
      });
      const newPassInputEl = newPassGroup.createEl("input", {
        type: "password",
        cls: "cloudsync-text-input",
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
        cls: "mod-cta cloudsync-primary-btn",
        text: this.isLoading ? "Resetting..." : "Reset Password & Sign In",
      });
      resetBtn.disabled = this.isLoading;
      resetBtn.onclick = () => this.handleRecoverySubmit();

      const switchMethodRow = authBox.createDiv({ cls: "cloudsync-switch-row" });
      const switchMethodLink = switchMethodRow.createEl("a", {
        cls: "cloudsync-inline-link",
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

      const backRow = authBox.createDiv({ cls: "cloudsync-switch-row" });
      const backLink = backRow.createEl("a", {
        cls: "cloudsync-inline-link",
        text: "← Back to Sign in",
      });
      backLink.onclick = () => {
        this.isRecoveryMode = false;
        this.errorMessage = null;
        this.display();
      };
    } else {
      const userGroup = form.createDiv({ cls: "cloudsync-input-group" });
      userGroup.createEl("label", { text: "Username", cls: "cloudsync-input-label" });
      const userInputEl = userGroup.createEl("input", {
        type: "text",
        cls: "cloudsync-text-input",
        value: this.usernameInput,
        placeholder: "username",
      });
      userInputEl.oninput = (e) => {
        this.usernameInput = (e.target as HTMLInputElement).value.trim();
        this.errorMessage = null;
      };

      const passGroup = form.createDiv({ cls: "cloudsync-input-group" });
      const passLabelRow = passGroup.createDiv({ cls: "cloudsync-label-row" });
      passLabelRow.createEl("label", {
        text: "Password",
        cls: "cloudsync-input-label",
      });

      if (!this.isRegisterMode) {
        const forgotLink = passLabelRow.createEl("span", {
          cls: "cloudsync-forgot-link",
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
        cls: "cloudsync-text-input",
        value: this.passwordInput,
      });
      passInputEl.oninput = (e) => {
        this.passwordInput = (e.target as HTMLInputElement).value;
        this.errorMessage = null;
      };
      passInputEl.onkeydown = (e) => {
        if (e.key === "Enter") this.handleMultiAuthSubmit();
      };

      if (this.requires2FA) {
        const totpGroup = form.createDiv({ cls: "cloudsync-input-group" });
        totpGroup.createEl("label", {
          text: "2FA Verification Code",
          cls: "cloudsync-input-label",
        });
        const totpInputEl = totpGroup.createEl("input", {
          type: "text",
          cls: "cloudsync-text-input",
          value: this.totpCodeInput,
          placeholder: "6-digit code",
        });
        totpInputEl.oninput = (e) => {
          this.totpCodeInput = (e.target as HTMLInputElement).value.trim();
          this.errorMessage = null;
        };
        totpInputEl.onkeydown = (e) => {
          if (e.key === "Enter") this.handleMultiAuthSubmit();
        };
      }

      const submitBtn = form.createEl("button", {
        cls: "mod-cta cloudsync-primary-btn",
        text: this.isLoading
          ? "Connecting..."
          : this.isRegisterMode
          ? "Create account"
          : "Sign in",
      });
      submitBtn.disabled = this.isLoading;
      submitBtn.onclick = () => this.handleMultiAuthSubmit();

      const switchRow = authBox.createDiv({ cls: "cloudsync-switch-row" });
      if (!this.isRegisterMode) {
        switchRow.createSpan({ text: "Don’t have an account? " });
        const switchLink = switchRow.createEl("a", {
          cls: "cloudsync-inline-link",
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
          cls: "cloudsync-inline-link",
          text: "Sign in",
        });
        switchLink.onclick = () => {
          this.isRegisterMode = false;
          this.errorMessage = null;
          this.display();
        };
      }
    }

    const changeUrlRow = authBox.createDiv({ cls: "cloudsync-switch-row" });
    changeUrlRow.style.marginTop = "14px";
    const changeUrlLink = changeUrlRow.createEl("a", {
      cls: "cloudsync-inline-link",
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

      new Notice("CloudSync connected successfully!");
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
          this.errorMessage = res.json?.error || "Registration failed.";
          this.isLoading = false;
          this.display();
          return;
        }

        cs.token = res.json.token;
        cs.userId = res.json.user?.id || "";
        cs.username = this.usernameInput;
        cs.vaultId = this.app.vault.getName();
        cs.encryptionKey = encryptionKey;
        cs.has2FA = false;
        this.plugin.settings.password = encryptionKey;
        this.plugin.settings.encryptionMethod = "rclone-base64";

        await this.plugin.saveSettings();
        await this.plugin.autoRegisterDevice();

        this.isLoading = false;
        new Notice("CloudSync account created!");

        new TwoFactorModal(this.app, this.plugin, "prompt", () => {
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

        if (res.status === 200 && res.json?.requires2FA) {
          this.requires2FA = true;
          this.isLoading = false;
          this.display();
          return;
        }

        if (res.status !== 200) {
          this.errorMessage =
            res.json?.error || "Invalid username or password.";
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

        new Notice("Successfully signed in to CloudSync!");
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
        this.errorMessage =
          res.json?.error || "Password reset failed. Please check your verification code.";
        this.isLoading = false;
        this.display();
        return;
      }

      cs.token = res.json.token;
      cs.userId = res.json.user?.id || "";
      cs.username = this.usernameInput;
      cs.vaultId = this.app.vault.getName();
      cs.encryptionKey = encryptionKey;
      cs.has2FA = Boolean(res.json.has2FA !== undefined ? res.json.has2FA : true);
      this.plugin.settings.password = encryptionKey;
      this.plugin.settings.encryptionMethod = "rclone-base64";

      await this.plugin.saveSettings();
      await this.plugin.autoRegisterDevice();

      new Notice("Password reset successful! Signed in to CloudSync.");
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
        .setClass("cloudsync-2fa-banner")
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

    if (cs.vaultId) {
      new Setting(containerEl)
        .setName("Remote vault")
        .setDesc(`Currently connected to the “${cs.vaultId}” remote vault.`)
        .addButton((btn) => {
          btn
            .setButtonText("Disconnect")
            .setClass("mod-destructive")
            .onClick(async () => {
              if (
                !confirm(
                  `Are you sure you want to disconnect from "${cs.vaultId}"?\n\nYour local files will not be deleted, but syncing will be paused until you connect to a vault.`
                )
              ) {
                return;
              }
              const disconnectedVault = cs.vaultId;
              cs.vaultId = "";
              await this.plugin.saveSettings();
              new Notice(`Disconnected from remote vault "${disconnectedVault}".`);
              this.display();
            });
        })
        .addButton((btn) => {
          btn
            .setButtonText("Switch")
            .onClick(() => {
              new VaultPickerModal(this.app, this.plugin, () => this.display()).open();
            });
        })
        .addButton((btn) => {
          btn
            .setButtonText("Manage")
            .onClick(() => {
              new VaultShareModal(this.app, this.plugin, cs.vaultId).open();
            });
        });
    } else {
      new Setting(containerEl)
        .setName("Remote vault")
        .setDesc(
          "No remote vault connected to this device. Choose an existing vault or create a new one to begin syncing."
        )
        .addButton((btn) => {
          btn
            .setButtonText("Choose")
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
          ? "Obsidian Sync is currently paused."
          : "Obsidian Sync is currently running."
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
      });

    initDeviceIdentity(this.plugin.settings);
    new Setting(containerEl)
      .setName("Device name")
      .setDesc("This name will be displayed in the activity log. Leave empty to use the default name.")
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

    new Setting(containerEl)
      .setName("Conflict resolution")
      .setDesc("Choose how conflicts are resolved when a note is independently modified on multiple devices.")
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
      .setName("Deleted files")
      .setDesc("View and restore deleted files.")
      .addButton((btn) => {
        btn
          .setButtonText("View")
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
      .setName("Sync log")
      .setDesc("View recent sync activities for debugging.")
      .addButton((btn) => {
        btn
          .setButtonText("View")
          .onClick(() => {
            new SyncLogModal(this.app, this.plugin).open();
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
        .setDesc(`You are using ${mb} MB out of ${gbLimit} GB (${pct}%)`);

      const barTrack = storageSetting.controlEl.createDiv({
        cls: "cloudsync-storage-track",
      });
      const barFill = barTrack.createDiv({ cls: "cloudsync-storage-fill" });
      barFill.style.width = `${Math.min(100, Math.max(1, Number.parseFloat(pct)))}%`;
    }

    containerEl.createEl("h3", { text: "Selective sync" });

    const ignoredFolders = this.plugin.settings.ignorePaths || [];
    const excludedDescFrag = createFragment((f) => {
      f.appendText("Prevent certain folders from being synced.");
      if (ignoredFolders.length > 0) {
        f.appendText(" These folders are currently excluded:");
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
          .setButtonText("Manage")
          .onClick(() => {
            new ExcludedFoldersModal(this.app, this.plugin).open();
          });
      });

    new Setting(containerEl)
      .setName("Sync images")
      .setDesc("Sync image files with these extensions: bmp, png, jpg, jpeg, gif, svg, webp.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncImages ?? true)
          .onChange(async (val) => {
            this.plugin.settings.syncImages = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync audio")
      .setDesc("Sync audio files with these extensions: mp3, wav, m4a, 3gp, flac, ogg, oga, opus.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncAudio ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncAudio = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync videos")
      .setDesc("Sync video files with these extensions: mp4, webm, ogv, mov, mkv.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncVideos ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncVideos = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync PDFs")
      .setDesc("Sync PDF files.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncPdfs ?? true)
          .onChange(async (val) => {
            this.plugin.settings.syncPdfs = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync all other types")
      .setDesc("Sync unsupported file types.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncUnsupported ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncUnsupported = val;
            await this.plugin.saveSettings();
          });
      });

    containerEl.createEl("h3", { text: "Vault configuration sync" });

    new Setting(containerEl)
      .setName("Main settings")
      .setDesc("Enable to sync editor settings, files & links settings, etc.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncMainSettings ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncMainSettings = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Appearance settings")
      .setDesc("Sync appearance settings like dark mode, active theme, and enabled snippets.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncAppearance ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncAppearance = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Themes and snippets")
      .setDesc("Sync downloaded themes and snippets. Whether they are enabled depends on the previous setting.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncAppearanceData ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncAppearanceData = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Hotkeys")
      .setDesc("Sync custom hotkeys.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncHotkeys ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncHotkeys = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Active core plugin list")
      .setDesc("Sync which core plugins are enabled.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncCorePlugins ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncCorePlugins = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Core plugin settings")
      .setDesc("Sync core plugin settings.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncCorePluginData ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncCorePluginData = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Active community plugin list")
      .setDesc("Sync which community plugins are enabled.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncCommunityPlugins ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncCommunityPlugins = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Installed community plugins")
      .setDesc("Sync installed community plugins (.js, .css, and manifest.json files) and their settings.")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.syncCommunityPluginData ?? false)
          .onChange(async (val) => {
            this.plugin.settings.syncCommunityPluginData = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Connected devices & backups")
      .setDesc("Device-specific configurations and snapshots for this vault")
      .setHeading()
      .addButton((btn) => {
        btn.setButtonText("Refresh").onClick(async () => {
          btn.setDisabled(true);
          btn.setButtonText("Refreshing...");
          await this.plugin.autoRegisterDevice().catch(() => {});
          this.display();
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
              new Notice(
                `CloudSync: Successfully backed up ${res.fileCount} settings files!`
              );
              btn.setButtonText("Backed up!");
              window.setTimeout(() => {
                btn.setDisabled(false);
                btn.setButtonText("Backup now");
              }, 2000);
            } catch (err: any) {
              btn.setDisabled(false);
              btn.setButtonText("Backup now");
              new Notice(
                `CloudSync: Failed to backup settings: ${err?.message || err}`
              );
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
        .then((devices: DeviceInfo[]) => {
          otherDevicesContainer.empty();
          const otherDevices = (devices || []).filter(
            (d) => d.deviceId !== this.plugin.settings.deviceId
          );

          if (otherDevices.length === 0) {
            new Setting(otherDevicesContainer)
              .setName("No other devices")
              .setDesc("No other devices detected on this vault yet.");
            return;
          }

          for (const dev of otherDevices) {
            const platformLabel =
              dev.platform === "mobile" ? "Mobile" : "Desktop";
            const backupDesc = dev.lastBackup
              ? `Last backed up: ${new Date(dev.lastBackup).toLocaleString()}${
                  dev.fileCount ? ` (${dev.fileCount} files)` : ""
                }`
              : "No backup created yet";

            new Setting(otherDevicesContainer)
              .setName(`${dev.deviceName} (${platformLabel})`)
              .setDesc(backupDesc)
              .addButton((restoreBtn) => {
                restoreBtn
                  .setButtonText("Restore to this device")
                  .setDisabled(!dev.lastBackup)
                  .onClick(async () => {
                    if (
                      !confirm(
                        `Restore settings from "${dev.deviceName}"?\n\nThis will apply themes, snippets, and plugin settings from that device to this one. Your notes will remain completely untouched.`
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
                        (msg) => new Notice(`CloudSync: ${msg}`, 1500)
                      );
                      restoreBtn.setButtonText("Restored!");
                      new Notice(
                        `CloudSync: Restored ${res.restoredCount} configuration files! Please reload Obsidian to apply changes.`,
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
                        `CloudSync: Failed to restore settings: ${
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

    containerEl.createEl("h3", { text: "Account & Automation" });

    new Setting(containerEl)
      .setName("Signed in as")
      .setDesc(cs.username || (cs.mode === "single" ? "Personal Worker" : "User"))
      .addButton((btn) => {
        btn
          .setButtonText("Log out")
          .setClass("mod-destructive")
          .onClick(async () => {
            if (
              !confirm(
                "Are you sure you want to log out of your CloudSync account on this device?"
              )
            ) {
              return;
            }
            cs.token = "";
            cs.username = "";
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
            new Notice("Logged out of CloudSync.");
            this.display();
          });
      });

    new Setting(containerEl)
      .setName("Server URL")
      .setDesc(cs.serverUrl);

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

    new Setting(containerEl)
      .setName("Sync on startup")
      .setDesc("Automatically sync when Obsidian opens")
      .addToggle((toggle) => {
        toggle
          .setValue((this.plugin.settings.initRunAfterMilliseconds ?? -1) > 0)
          .onChange(async (val) => {
            this.plugin.settings.initRunAfterMilliseconds = val ? 2000 : -1;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Sync on save / edit")
      .setDesc("Sync automatically a few seconds after changes")
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
      .setDesc(
        "Display a pop-up notice whenever files are synced. Disabled by default to avoid alerts on small edits."
      )
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.showSyncNotifications ?? false)
          .onChange(async (val) => {
            this.plugin.settings.showSyncNotifications = val;
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Auto-sync interval")
      .setDesc("Periodically sync notes in the background")
      .addDropdown((drop) => {
        drop
          .addOption("-1", "Disabled")
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
      .setName("Safety protection threshold")
      .setDesc(
        "Prevent accidental deletion if too many notes are deleted at once"
      )
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
      }
    } catch {
      // Ignore background storage check failure
    }
  }
}
