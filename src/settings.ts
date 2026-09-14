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
import type CloudSyncPlugin from "./main";

export class CloudSyncSettingTab extends PluginSettingTab {
  plugin: CloudSyncPlugin;

  // View state
  private isRegisterMode = false;
  private isRecoveryMode = false;
  private requires2FA = false;

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

  // ===========================================================================
  // 1. STEP 1: WORKER URL PROMPT
  // ===========================================================================
  private renderServerUrlPrompt(containerEl: HTMLElement) {
    const authWrapper = containerEl.createDiv({ cls: "cloudsync-auth-wrapper" });
    const authBox = authWrapper.createDiv({ cls: "cloudsync-auth-box" });

    // Logo
    const logoEl = authBox.createDiv({ cls: "cloudsync-auth-logo" });
    logoEl.createEl("img", {
      cls: "cloudsync-logo-img",
      attr: { src: OBSIDIAN_LOGO_PNG, alt: "Obsidian" },
    });

    // Title & Subtitle
    authBox.createDiv({
      cls: "cloudsync-auth-title",
      text: "Connect to CloudSync",
    });
    authBox.createDiv({
      cls: "cloudsync-auth-subtitle",
      text: "Enter your self-hosted Cloudflare Worker URL to begin.",
    });

    // Error banner
    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "cloudsync-error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "cloudsync-auth-form" });

    // Worker URL input
    const urlGroup = form.createDiv({ cls: "cloudsync-input-group" });
    urlGroup.createEl("label", {
      text: "Worker URL",
      cls: "cloudsync-input-label",
    });
    const urlInputEl = urlGroup.createEl("input", {
      type: "url",
      cls: "cloudsync-text-input",
      value: this.serverUrlInput,
      placeholder: "https://my-sync.username.workers.dev",
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

    // Connect button
    const connectBtn = form.createEl("button", {
      cls: "mod-cta cloudsync-primary-btn",
      text: this.isLoading ? "Connecting..." : "Connect to Worker",
    });
    connectBtn.disabled = this.isLoading;
    connectBtn.onclick = () => {
      this.handleConnectWorker();
    };
  }

  private async handleConnectWorker() {
    const url = (this.serverUrlInput || "").trim().replace(/\/+$/, "");
    if (!url || !url.startsWith("http")) {
      this.errorMessage = "Please enter a valid Worker URL starting with https://";
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
          throw new Error("Target server does not appear to be a CloudSync worker.");
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

  // ===========================================================================
  // 2. STEP 2: AUTH PROMPT (SINGLE-USER VS MULTI-USER)
  // ===========================================================================
  private renderAuthPrompt(containerEl: HTMLElement) {
    const cs = this.plugin.settings.cloudsync;
    const isSingleMode = cs.mode === "single";

    const authWrapper = containerEl.createDiv({ cls: "cloudsync-auth-wrapper" });
    const authBox = authWrapper.createDiv({ cls: "cloudsync-auth-box" });

    // Logo
    const logoEl = authBox.createDiv({ cls: "cloudsync-auth-logo" });
    logoEl.createEl("img", {
      cls: "cloudsync-logo-img",
      attr: { src: OBSIDIAN_LOGO_PNG, alt: "Obsidian" },
    });

    // Title & Subtitle
    if (isSingleMode) {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Unlock CloudSync",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: `Personal worker: ${cs.serverUrl}`,
      });
    } else if (this.isRecoveryMode) {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Reset your password",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: "Enter your username and recovery key to set a new password.",
      });
    } else if (this.isRegisterMode) {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Create an account",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: `Worker: ${cs.serverUrl}`,
      });
    } else {
      authBox.createDiv({
        cls: "cloudsync-auth-title",
        text: "Sign in to CloudSync",
      });
      authBox.createDiv({
        cls: "cloudsync-auth-subtitle",
        text: `Worker: ${cs.serverUrl}`,
      });
    }

    // Error banner
    if (this.errorMessage) {
      const errorEl = authBox.createDiv({ cls: "cloudsync-error-banner" });
      errorEl.createSpan({ text: this.errorMessage });
    }

    const form = authBox.createDiv({ cls: "cloudsync-auth-form" });

    if (isSingleMode) {
      // -----------------------------------------------------------------------
      // Single-User Mode: Only Password
      // -----------------------------------------------------------------------
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
      // -----------------------------------------------------------------------
      // Multi-User: Recovery Mode
      // -----------------------------------------------------------------------
      const userGroup = form.createDiv({ cls: "cloudsync-input-group" });
      userGroup.createEl("label", { text: "Username", cls: "cloudsync-input-label" });
      const userInputEl = userGroup.createEl("input", {
        type: "text",
        cls: "cloudsync-text-input",
        value: this.usernameInput,
      });
      userInputEl.oninput = (e) => {
        this.usernameInput = (e.target as HTMLInputElement).value.trim();
        this.errorMessage = null;
      };

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

      const newPassGroup = form.createDiv({ cls: "cloudsync-input-group" });
      newPassGroup.createEl("label", {
        text: "New Password",
        cls: "cloudsync-input-label",
      });
      const newPassInputEl = newPassGroup.createEl("input", {
        type: "password",
        cls: "cloudsync-text-input",
        value: this.passwordInput,
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
      // -----------------------------------------------------------------------
      // Multi-User: Sign in / Create account
      // -----------------------------------------------------------------------
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

      // If 2FA is required during login
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

      // Submit Button (Frictionless: Username + Password only!)
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

      // Switch between Sign In and Register
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

    // Change Worker URL footer link
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

  // ---------------------------------------------------------------------------
  // Single-User Auth Handler
  // ---------------------------------------------------------------------------
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

  // ---------------------------------------------------------------------------
  // Multi-User Auth Handler
  // ---------------------------------------------------------------------------
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

        // Open 2FA setup prompt immediately as requested!
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

  // ---------------------------------------------------------------------------
  // Account Recovery Handler
  // ---------------------------------------------------------------------------
  private async handleRecoverySubmit() {
    if (!this.usernameInput || !this.recoveryKeyInput || !this.passwordInput) {
      this.errorMessage = "Please enter username, recovery key, and new password.";
      this.display();
      return;
    }

    this.isLoading = true;
    this.errorMessage = null;
    this.display();

    const cs = this.plugin.settings.cloudsync;
    try {
      const recoveryVerifier = await deriveRecoveryVerifier(this.recoveryKeyInput);
      const { authVerifier, encryptionKey } = await deriveZeroKnowledgeKeys(
        this.usernameInput,
        this.passwordInput
      );

      const res = await requestUrl({
        url: `${cs.serverUrl}/api/auth/recover`,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          username: this.usernameInput,
          recoveryVerifier,
          newVerifier: authVerifier,
        }),
        throw: false,
      });

      if (res.status !== 200) {
        this.errorMessage = res.json?.error || "Password reset failed. Check your recovery key.";
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

  // ===========================================================================
  // 3. LOGGED IN VIEW (EXACT OBSIDIAN NATIVE SETTINGS)
  // ===========================================================================
  private async renderLoggedInView(containerEl: HTMLElement) {
    const cs = this.plugin.settings.cloudsync;

    // SECTION 0: 2FA REMINDER BANNER (If multi-user mode and 2FA not set up)
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

    // SECTION 1: ACCOUNT
    containerEl.createEl("h3", { text: "Account" });

    new Setting(containerEl)
      .setName("Worker URL")
      .setDesc(cs.serverUrl)
      .addButton((btn) => {
        btn
          .setButtonText("Disconnect")
          .setWarning()
          .onClick(async () => {
            cs.token = "";
            cs.username = "";
            cs.email = "";
            cs.encryptionKey = "";
            this.plugin.settings.password = "";
            await this.plugin.saveSettings();
            new Notice("Disconnected from CloudSync.");
            this.display();
          });
      });

    new Setting(containerEl)
      .setName("Signed in as")
      .setDesc(cs.username || (cs.mode === "single" ? "Personal Worker" : "User"));

    // Two-factor authentication row in account
    if (cs.mode === "multi") {
      new Setting(containerEl)
        .setName("Two-factor authentication")
        .setDesc(cs.has2FA ? "Enabled (Authenticator app)" : "Not enabled")
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

    // Storage usage
    await this.fetchStorageUsage();
    if (this.storageUsedBytes !== null) {
      const mb = (this.storageUsedBytes / (1024 * 1024)).toFixed(2);
      const gbLimit = 10;
      const pct = (
        (this.storageUsedBytes / (10 * 1024 * 1024 * 1024)) *
        100
      ).toFixed(2);

      const storageSetting = new Setting(containerEl)
        .setName("Storage used")
        .setDesc(`${mb} MB of ${gbLimit} GB (${pct}%)`);

      const barTrack = storageSetting.controlEl.createDiv({
        cls: "cloudsync-storage-track",
      });
      const barFill = barTrack.createDiv({ cls: "cloudsync-storage-fill" });
      barFill.style.width = `${Math.min(100, Math.max(1, Number.parseFloat(pct)))}%`;
    }

    // SECTION 2: SYNC
    containerEl.createEl("h3", { text: "Sync" });

    new Setting(containerEl)
      .setName("Sync status")
      .setDesc(`Remote vault: ${cs.vaultId || this.app.vault.getName()}`)
      .addButton((btn) => {
        btn
          .setButtonText("Sync now")
          .setCta()
          .onClick(async () => {
            new Notice("Starting sync...");
            await this.plugin.syncRun("manual");
          });
      });

    // SECTION 3: SYNC PREFERENCES
    containerEl.createEl("h3", { text: "Sync settings" });

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
      .setName("Vault settings sync mode")
      .setDesc(
        "Choose whether to sync Obsidian settings (.obsidian) or isolate them per device"
      )
      .addDropdown((drop) => {
        drop
          .addOption("notes_only", "Notes only")
          .addOption("device_isolated", "Device-isolated backups")
          .addOption("shared", "Shared settings")
          .setValue(this.plugin.settings.settingsSyncMode ?? "notes_only")
          .onChange(async (val: any) => {
            this.plugin.settings.settingsSyncMode = val;
            this.plugin.settings.syncConfigDir = val === "shared";
            await this.plugin.saveSettings();
            this.display();
          });
      });

    // Device Settings & Backups (Pure Obsidian Native Layout)
    if (this.plugin.settings.settingsSyncMode !== "shared") {
      initDeviceIdentity(this.plugin.settings);

      new Setting(containerEl)
        .setName("This device name")
        .setDesc(`Device ID: ${this.plugin.settings.deviceId}`)
        .addText((text) => {
          text
            .setValue(this.plugin.settings.deviceName ?? "My Device")
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

      // Heading for Connected Devices & Backups with inline Refresh button
      new Setting(containerEl)
        .setName("Connected devices & backups")
        .setDesc("Device-specific configurations for this vault")
        .setHeading()
        .addButton((btn) => {
          btn.setButtonText("Refresh").onClick(async () => {
            btn.setDisabled(true);
            btn.setButtonText("Refreshing...");
            await this.plugin.autoRegisterDevice().catch(() => {});
            this.display();
          });
        });

      // Item 1: This Device
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

      // Other Devices Container
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
    }

    new Setting(containerEl)
      .setName("Conflict resolution")
      .setDesc("How to handle simultaneous edits on different devices")
      .addDropdown((drop) => {
        drop
          .addOption("keep_newer", "Keep newer file")
          .addOption("smart_conflict", "Smart merge")
          .addOption("keep_larger", "Keep larger file")
          .setValue(this.plugin.settings.conflictAction ?? "keep_newer")
          .onChange(async (val: any) => {
            this.plugin.settings.conflictAction = val;
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
        if (res.json?.has2FA !== undefined) {
          cs.has2FA = res.json.has2FA;
        }
      }
    } catch {
      // Ignore background storage check failure
    }
  }
}
