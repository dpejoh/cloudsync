import cloneDeep from "lodash/cloneDeep";
import throttle from "lodash/throttle";
import { FileText, RefreshCcw, RotateCcw, createElement } from "lucide";
import {
  Events,
  FileSystemAdapter,
  Menu,
  Notice,
  Platform,
  Plugin,
  TFile,
  TFolder,
  addIcon,
  requestUrl,
  setIcon,
} from "obsidian";
import type {
  CloudSyncConfig,
  RemotelySavePluginSettings,
  SyncTriggerSourceType,
} from "./baseTypes";
import type { SyncLogEntry } from "./syncLogModal";
import { SyncLogModal } from "./syncLogModal";
import { DeletedFilesModal } from "./deletedFilesModal";
import { VersionHistoryModal } from "./versionHistoryModal";
import { VaultPickerModal } from "./vaultPickerModal";
import {
  COMMAND_URI,
  DEFAULT_CLOUDSYNC_CONFIG,
  DEFAULT_DEBUG_FOLDER,
  DEFAULT_DEVICE_CONFIGS_FOLDER,
} from "./baseTypes";
import {
  initDeviceIdentity,
  backupDeviceSettings,
  restoreDeviceSettings,
} from "./deviceSettings";
import { messyConfigToNormal, normalConfigToMessy } from "./configPersist";
import { exportVaultSyncPlansToFiles } from "./debugMode";
import { fastPullChange, fastPushPath } from "./fastSync";
import { FakeFsEncrypt } from "./fsEncrypt";
import { getClient } from "./fsGetter";
import { FakeFsLocal } from "./fsLocal";
import { FakeFsWorker, type VaultChangeItem } from "./fsWorker";
import { I18n } from "./i18n";
import type { LangTypeAndAuto, TransItemType } from "./i18n";
import { importQrCodeUri } from "./importExport";
import {
  type InternalDBs,
  clearAllLoggerOutputRecords,
  clearExpiredSyncPlanRecords,
  getLatestVaultRevision,
  getLastFailedSyncTimeByVault,
  getLastSuccessSyncTimeByVault,
  prepareDBs,
  saveLatestVaultRevision,
  upsertLastFailedSyncTimeByVault,
  upsertLastSuccessSyncTimeByVault,
  upsertPluginVersionByVault,
} from "./localdb";
import {
  changeMobileStatusBar,
  isHiddenPath,
  isSpecialFolderNameToSkip,
} from "./misc";
import { DEFAULT_PROFILER_CONFIG, Profiler } from "./profiler";
import { CloudSyncSettingTab } from "./settings";
import { syncer } from "./sync";

const DEFAULT_SETTINGS: RemotelySavePluginSettings = {
  cloudsync: DEFAULT_CLOUDSYNC_CONFIG,
  password: "",
  serviceType: "cloudsync",
  currLogLevel: "info",
  autoRunEveryMilliseconds: 300000, // 5 min
  initRunAfterMilliseconds: 2000,
  syncOnSaveAfterMilliseconds: 2000,
  concurrency: 5,
  syncConfigDir: false,
  syncBookmarks: false,
  syncUnderscoreItems: false,
  lang: "auto",
  skipSizeLargerThan: -1,
  ignorePaths: [],
  onlyAllowPaths: [],
  enableStatusBarInfo: true,
  deleteToWhere: "system",
  agreeToUseSyncV3: true,
  conflictAction: "keep_newer",
  protectModifyPercentage: 50,
  syncDirection: "bidirectional",
  obfuscateSettingFile: true,
  enableMobileStatusBar: true,
  encryptionMethod: "rclone-base64",
  profiler: DEFAULT_PROFILER_CONFIG,
  settingsSyncMode: "notes_only",
  isSyncPaused: false,
  syncImages: true,
  syncAudio: false,
  syncVideos: false,
  syncPdfs: true,
  syncUnsupported: false,
  syncMainSettings: false,
  syncAppearance: false,
  syncAppearanceData: false,
  syncHotkeys: false,
  syncCorePlugins: false,
  syncCorePluginData: false,
  syncCommunityPlugins: false,
  syncCommunityPluginData: false,
  showSyncNotifications: false,
};

const iconNameSyncWait = `cloudsync-sync-wait`;
const iconNameSyncRunning = `cloudsync-sync-running`;
const iconNameLogs = `cloudsync-logs`;

const getIconSvg = () => {
  const iconSvgSyncWait = createElement(RotateCcw);
  iconSvgSyncWait.setAttribute("width", "100");
  iconSvgSyncWait.setAttribute("height", "100");
  const iconSvgSyncRunning = createElement(RefreshCcw);
  iconSvgSyncRunning.setAttribute("width", "100");
  iconSvgSyncRunning.setAttribute("height", "100");
  const iconSvgLogs = createElement(FileText);
  iconSvgLogs.setAttribute("width", "100");
  iconSvgLogs.setAttribute("height", "100");
  return {
    iconSvgSyncWait: iconSvgSyncWait.outerHTML,
    iconSvgSyncRunning: iconSvgSyncRunning.outerHTML,
    iconSvgLogs: iconSvgLogs.outerHTML,
  };
};

export default class CloudSyncPlugin extends Plugin {
  settings!: RemotelySavePluginSettings;
  db!: InternalDBs;
  vaultRandomID!: string;
  currSyncMsg?: string;
  isSyncing = false;
  syncRibbon?: HTMLElement;
  statusBarElement?: HTMLSpanElement;
  autoRunIntervalID?: number;
  syncOnSaveIntervalID?: number;
  hasPendingSyncOnSave = false;
  syncEvent?: Events;
  i18n!: I18n;
  appContainerObserver?: MutationObserver;

  cachedFsLocal?: FakeFsLocal;
  cachedFsRemote?: FakeFsWorker;
  cachedFsEncrypt?: FakeFsEncrypt;
  cachedFsEncryptPassword?: string;
  cachedFsEncryptMethod?: string;

  debouncePushTimer?: number;
  pendingModifiedPaths: Set<string> = new Set<string>();
  suppressLocalEvents: Set<string> = new Set<string>();
  livePulseIntervalID?: number;
  isFastSyncing = false;
  lastKnownRevision = 0;

  lastLocalCursor: { path: string; line: number; ch: number } | null = null;
  cursorDebounceTimer?: number;
  isApplyingRemoteCursor = false;

  syncLogs: SyncLogEntry[] = [];

  addSyncLog(entry: {
    type: "info" | "success" | "error" | "skipped" | "conflict";
    message: string;
    file?: string;
  }) {
    this.syncLogs.unshift({
      id: Math.random().toString(36).slice(2),
      timestamp: Date.now(),
      type: entry.type,
      message: entry.message,
      file: entry.file,
    });
    if (this.syncLogs.length > 300) {
      this.syncLogs.pop();
    }
  }

  getOrCreateClients() {
    const vaultName = this.app.vault.getName();
    const profileID = this.getCurrProfileID();

    const syncConfigDir =
      (this.settings.settingsSyncMode ?? "notes_only") === "shared";

    if (!this.cachedFsLocal) {
      this.cachedFsLocal = new FakeFsLocal(
        this.app.vault,
        syncConfigDir,
        this.settings.syncBookmarks ?? false,
        this.app.vault.configDir,
        this.manifest.id,
        undefined,
        this.settings.deleteToWhere ?? "system"
      );
    }

    if (!this.cachedFsRemote) {
      this.cachedFsRemote = new FakeFsWorker(
        this.settings.cloudsync,
        vaultName
      );
    }

    if (
      !this.cachedFsEncrypt ||
      this.cachedFsEncryptPassword !== this.settings.password ||
      this.cachedFsEncryptMethod !== this.settings.encryptionMethod
    ) {
      if (this.cachedFsEncrypt) {
        this.cachedFsEncrypt.closeResources();
      }
      this.cachedFsEncryptPassword = this.settings.password;
      this.cachedFsEncryptMethod =
        this.settings.encryptionMethod || "rclone-base64";
      this.cachedFsEncrypt = new FakeFsEncrypt(
        this.cachedFsRemote,
        this.settings.password,
        this.settings.encryptionMethod || "rclone-base64"
      );
    }

    return {
      fsLocal: this.cachedFsLocal,
      fsRemote: this.cachedFsRemote,
      fsEncrypt: this.cachedFsEncrypt,
      profileID,
    };
  }

  async autoRegisterDevice() {
    if (!this.settings.cloudsync?.token) return;
    initDeviceIdentity(this.settings);
    const { fsRemote } = this.getOrCreateClients();
    if (fsRemote && typeof (fsRemote as any).registerDevice === "function") {
      try {
        await fsRemote.registerDevice({
          deviceId: this.settings.deviceId!,
          deviceName: this.settings.deviceName!,
          platform: Platform.isMobile ? "mobile" : "desktop",
          lastBackup: this.settings.lastSettingsBackupTime,
        });
      } catch (err) {
        console.debug("CloudSync: Device registration heartbeat skipped:", err);
      }
    }
    await this.refreshUserProfile().catch(() => {});
  }

  async refreshUserProfile() {
    const cs = this.settings.cloudsync;
    if (!cs?.serverUrl || !cs?.token) return;
    try {
      const res = await requestUrl({
        url: `${cs.serverUrl}/api/user/me`,
        method: "GET",
        headers: { Authorization: `Bearer ${cs.token}` },
        throw: false,
      });
      if (res.status === 200 && res.json?.has2FA !== undefined) {
        if (cs.has2FA !== res.json.has2FA) {
          cs.has2FA = res.json.has2FA;
          await this.saveSettings();
        }
      }
    } catch {
      // Ignore background check failure
    }
  }

  openStatusIconMenu(e: MouseEvent) {
    const menu = new Menu();

    const hasVault = !!this.settings.cloudsync?.vaultId;
    const statusText = !hasVault
      ? "Not connected"
      : this.isSyncing
      ? "Syncing..."
      : this.settings.isSyncPaused
      ? "Paused"
      : "Synced";

    menu.addItem((item) => {
      item.setTitle(`Sync: ${statusText}`).setDisabled(true);
    });

    menu.addSeparator();

    const isPaused = this.settings.isSyncPaused ?? false;
    menu.addItem((item) => {
      item
        .setTitle(isPaused ? "Resume" : "Pause")
        .setIcon(isPaused ? "lucide-play-circle" : "lucide-pause-circle")
        .setDisabled(!hasVault)
        .onClick(async () => {
          this.settings.isSyncPaused = !isPaused;
          await this.saveSettings();
          new Notice(
            this.settings.isSyncPaused ? "CloudSync: Paused" : "CloudSync: Resumed"
          );
          if (!this.settings.isSyncPaused) {
            this.syncRun("manual");
          }
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("Sync now")
        .setIcon("lucide-refresh-cw")
        .setDisabled(!hasVault)
        .onClick(async () => {
          await this.syncRun("manual");
        });
    });

    const activeFile = this.app.workspace.getActiveFile();
    menu.addItem((item) => {
      item
        .setTitle("Version history")
        .setIcon("lucide-history")
        .setDisabled(!activeFile || !hasVault)
        .onClick(() => {
          if (activeFile) {
            new VersionHistoryModal(this.app, this, activeFile.path).open();
          }
        });
    });

    menu.addSeparator();

    menu.addItem((item) => {
      item
        .setTitle("Choose remote vault")
        .setIcon("lucide-folder-sync")
        .onClick(() => {
          new VaultPickerModal(this.app, this).open();
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("Sync log")
        .setIcon("lucide-align-left")
        .onClick(() => {
          new SyncLogModal(this.app, this).open();
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("Deleted files")
        .setIcon("lucide-trash-2")
        .setDisabled(!hasVault)
        .onClick(() => {
          new DeletedFilesModal(this.app, this, false).open();
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("Settings")
        .setIcon("lucide-settings")
        .onClick(() => {
          (this.app as any).setting?.open?.();
          (this.app as any).setting?.openTabById?.(this.manifest.id);
        });
    });

    menu.showAtMouseEvent(e);
  }

  async syncRun(triggerSource: SyncTriggerSourceType = "manual") {
    const t = (x: TransItemType, vars?: any) => {
      return this.i18n.t(x, vars);
    };

    if (this.settings.isSyncPaused && triggerSource !== "manual") {
      return;
    }

    if (!this.settings.cloudsync.token) {
      new Notice("CloudSync: Please log in via settings to start syncing.");
      return;
    }

    if (!this.settings.cloudsync.vaultId) {
      new Notice("CloudSync: Please choose a remote vault in settings to start syncing.");
      return;
    }

    this.addSyncLog({
      type: "info",
      message: `Sync started (${triggerSource})`,
    });

    const { fsLocal, fsRemote, fsEncrypt, profileID } = this.getOrCreateClients();

    const markIsSyncingFunc = (status: boolean) => {
      this.isSyncing = status;
      if (!status) {
        this.currSyncMsg = "";
      }
    };

    const notifyFunc = async (s: SyncTriggerSourceType, step: number) => {
      if (s === "manual" && step === 0) {
        new Notice("CloudSync: Starting sync...");
      }
    };

    const errNotifyFunc = async (s: SyncTriggerSourceType, err: any) => {
      this.addSyncLog({
        type: "error",
        message: `Sync error: ${err?.message || err}`,
      });
      new Notice(`CloudSync Error: ${err?.message || err}`);
    };

    const ribboonFunc = async (s: SyncTriggerSourceType, step: number) => {
      if (this.syncRibbon) {
        if (step === 1 || step === 2) {
          setIcon(this.syncRibbon, iconNameSyncRunning);
        } else {
          setIcon(this.syncRibbon, iconNameSyncWait);
        }
      }
    };

    const statusBarFunc = async (
      s: SyncTriggerSourceType,
      step: number,
      everythingOk: boolean
    ) => {
      if (this.statusBarElement) {
        if (step === 1 || step === 2) {
          this.statusBarElement.setText("CloudSync: Syncing...");
        } else if (everythingOk) {
          this.statusBarElement.setText("CloudSync: Synced");
        } else {
          this.statusBarElement.setText("CloudSync: Failed");
        }
      }
    };

    const getProtectError = (
      protectModifyPercentage: number,
      realModifyDeleteCount: number,
      allFilesCount: number
    ) => {
      return `Safety protection triggered: ${realModifyDeleteCount}/${allFilesCount} files modified or deleted, exceeding your ${protectModifyPercentage}% safety threshold.`;
    };

    const callbackSyncProcess = async (
      s: SyncTriggerSourceType,
      counter: number,
      total: number,
      path: string,
      decision: string
    ) => {
      this.setCurrSyncMsg(t, s, counter, total, path, decision, triggerSource);
      if (decision.includes("push")) {
        this.addSyncLog({
          type: "success",
          message: `Uploaded ${path}`,
          file: path,
        });
      } else if (decision.includes("pull")) {
        this.addSyncLog({
          type: "success",
          message: `Downloaded ${path}`,
          file: path,
        });
      } else if (decision.includes("delete")) {
        this.addSyncLog({
          type: "info",
          message: `Deleted ${path}`,
          file: path,
        });
      }
    };

    if (this.isSyncing) {
      new Notice("CloudSync is already running.");
      return;
    }

    const configSaver = async () => await this.saveSettings();

    try {
      await syncer(
        fsLocal,
        fsRemote,
        fsEncrypt,
        undefined,
        this.db,
        triggerSource,
        profileID,
        this.vaultRandomID,
        this.app.vault.configDir,
        this.settings,
        this.manifest.version,
        configSaver,
        getProtectError,
        markIsSyncingFunc,
        notifyFunc,
        errNotifyFunc,
        ribboonFunc,
        statusBarFunc,
        callbackSyncProcess
      );
    } catch (err: any) {
      console.error("CloudSync syncer error:", err);
      this.addSyncLog({
        type: "error",
        message: `Sync failed: ${err?.message || err}`,
      });
      new Notice(`CloudSync failed: ${err?.message || err}`);
    } finally {
      if (this.cachedFsRemote?.latestRevision) {
        this.lastKnownRevision = Math.max(
          this.lastKnownRevision,
          this.cachedFsRemote.latestRevision
        );
        await saveLatestVaultRevision(
          this.db,
          this.vaultRandomID,
          profileID,
          this.lastKnownRevision
        );
      }
      await this.refreshUserProfile().catch(() => {});
      this.addSyncLog({
        type: "info",
        message: "Sync completed.",
      });
      this.syncEvent?.trigger("SYNC_DONE");
    }
  }

  async onload() {
    console.info(`Loading ${this.manifest.name} (${this.manifest.version})`);

    const { iconSvgSyncWait, iconSvgSyncRunning, iconSvgLogs } = getIconSvg();
    addIcon(iconNameSyncWait, iconSvgSyncWait);
    addIcon(iconNameSyncRunning, iconSvgSyncRunning);
    addIcon(iconNameLogs, iconSvgLogs);

    this.currSyncMsg = "";
    this.isSyncing = false;
    this.hasPendingSyncOnSave = false;
    this.syncEvent = new Events();

    await this.loadSettings();

    const profileID: string = this.getCurrProfileID();

    this.i18n = new I18n(this.settings.lang!, async (lang: LangTypeAndAuto) => {
      this.settings.lang = lang;
      await this.saveSettings();
    });

    const vaultBasePath = this.getVaultBasePath();
    const vaultRandomIDFromOld = await this.getVaultRandomIDFromOldConfigFile();

    await this.prepareDBAndVaultRandomID(
      vaultBasePath,
      vaultRandomIDFromOld,
      profileID
    );

    // Register protocol handler for settings import if needed
    this.registerObsidianProtocolHandler(COMMAND_URI, async (inputParams) => {
      const parsed = importQrCodeUri(inputParams, this.app.vault.getName());
      if (parsed.status === "error") {
        new Notice(parsed.message);
      } else {
        this.settings = Object.assign({}, this.settings, parsed.result);
        await this.saveSettings();
        new Notice("CloudSync settings imported successfully.");
      }
    });

    // Ribbon icon
    this.syncRibbon = this.addRibbonIcon(
      iconNameSyncWait,
      "CloudSync: Sync Now",
      async () => this.syncRun("manual")
    );

    // Status bar item
    if (this.settings.enableStatusBarInfo) {
      const statusBarItem = this.addStatusBarItem();
      this.statusBarElement = statusBarItem.createEl("span");
      this.statusBarElement.setText("CloudSync: Ready");
      this.statusBarElement.addClass("mod-clickable");
      statusBarItem.addClass("mod-clickable");
      statusBarItem.addEventListener("click", (evt) => {
        this.openStatusIconMenu(evt);
      });
    }

    // Context menu: File Explorer
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu, file) => {
        if (file instanceof TFile) {
          menu.addItem((item) => {
            item
              .setTitle("Open version history")
              .setIcon("lucide-history")
              .setSection("view")
              .onClick(() => {
                new VersionHistoryModal(this.app, this, file.path).open();
              });
          });
        }
      })
    );

    // Context menu: Editor
    this.registerEvent(
      this.app.workspace.on("editor-menu", (menu, editor, view) => {
        const file = view.file;
        if (file instanceof TFile) {
          menu.addItem((item) => {
            item
              .setTitle("Open version history")
              .setIcon("lucide-history")
              .setSection("view")
              .onClick(() => {
                new VersionHistoryModal(this.app, this, file.path).open();
              });
          });
        }
      })
    );

    // Commands
    this.addCommand({
      id: "cloudsync-version-history",
      name: "Open version history for current file",
      icon: "lucide-history",
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (file) {
          if (!checking) {
            new VersionHistoryModal(this.app, this, file.path).open();
          }
          return true;
        }
        return false;
      },
    });

    this.addCommand({
      id: "cloudsync-choose-vault",
      name: "Choose remote vault",
      icon: "lucide-folder-sync",
      callback: () => {
        new VaultPickerModal(this.app, this).open();
      },
    });

    this.addCommand({
      id: "cloudsync-sync-now",
      name: "Sync Vault Now",
      icon: iconNameSyncWait,
      callback: async () => {
        await this.syncRun("manual");
      },
    });

    this.addCommand({
      id: "cloudsync-dry-run",
      name: "Dry Run (Preview Changes)",
      icon: iconNameSyncWait,
      callback: async () => {
        await this.syncRun("dry");
      },
    });

    this.addCommand({
      id: "cloudsync-backup-device-settings",
      name: "Backup Settings for This Device to Cloud",
      callback: async () => {
        const { fsEncrypt, fsRemote } = this.getOrCreateClients();
        const notice = new Notice("CloudSync: Backing up device settings...", 0);
        try {
          const res = await backupDeviceSettings(
            this.app,
            fsEncrypt,
            fsRemote as FakeFsWorker,
            this.settings,
            (msg) => notice.setMessage(`CloudSync: ${msg}`)
          );
          await this.saveSettings();
          notice.hide();
          new Notice(`CloudSync: Backed up ${res.fileCount} settings files to cloud.`);
        } catch (err: any) {
          notice.hide();
          new Notice(`CloudSync: Failed to backup settings: ${err?.message || err}`);
        }
      },
    });

    // Add settings tab
    this.addSettingTab(new CloudSyncSettingTab(this.app, this));

    // Enable file stat checking for real-time sync-on-save
    this.enableCheckingFileStat();

    // Initialize real-time live pulse and change tracking
    await this.initRealtimeSync(profileID);

    // Register device identity with cloud registry
    await this.autoRegisterDevice();

    // Auto-sync intervals
    this.enableAutoSyncIfSet();
    this.enableInitSyncIfSet();
    this.toggleSyncOnSaveIfSet();

    await upsertPluginVersionByVault(
      this.db,
      this.vaultRandomID,
      this.manifest.version
    );
  }

  async onunload() {
    console.info(`Unloading plugin ${this.manifest.id}`);
    this.syncRibbon = undefined;
    if (this.autoRunIntervalID) {
      window.clearInterval(this.autoRunIntervalID);
    }
    if (this.livePulseIntervalID) {
      window.clearInterval(this.livePulseIntervalID);
    }
    if (this.syncOnSaveIntervalID) {
      window.clearInterval(this.syncOnSaveIntervalID);
    }
    if (this.debouncePushTimer) {
      window.clearTimeout(this.debouncePushTimer);
    }
    if (this.cursorDebounceTimer) {
      window.clearTimeout(this.cursorDebounceTimer);
    }
    if (this.cachedFsEncrypt) {
      this.cachedFsEncrypt.closeResources();
    }
  }

  async initRealtimeSync(profileID: string) {
    this.lastKnownRevision = await getLatestVaultRevision(
      this.db,
      this.vaultRandomID,
      profileID
    );

    // Foreground visibility listener: pull immediately when app is opened / focused
    this.registerDomEvent(document, "visibilitychange", async () => {
      if (document.visibilityState === "visible") {
        await this.runLivePulse();
      }
    });

    // Cursor movement listener (cross-device cursor sync)
    const doc =
      typeof activeDocument !== "undefined" ? activeDocument : window.document;
    const handleCursorMove = () => {
      if (
        this.isSyncing ||
        this.isFastSyncing ||
        this.isApplyingRemoteCursor
      ) {
        return;
      }
      const leaves = this.app.workspace.getLeavesOfType("markdown");
      if (leaves.length === 0) return;

      const activeView = this.app.workspace.activeLeaf?.view as any;
      if (!activeView || !activeView.file || !activeView.editor) return;

      const cur = activeView.editor.getCursor();
      const path = activeView.file.path;

      if (this.shouldIgnorePath(path)) return;

      if (
        this.lastLocalCursor &&
        this.lastLocalCursor.path === path &&
        this.lastLocalCursor.line === cur.line &&
        this.lastLocalCursor.ch === cur.ch
      ) {
        return;
      }

      this.lastLocalCursor = { path, line: cur.line, ch: cur.ch };

      if (this.cursorDebounceTimer) {
        window.clearTimeout(this.cursorDebounceTimer);
      }
      this.cursorDebounceTimer = window.setTimeout(async () => {
        await this.sendCursorUpdate(path, cur);
      }, 400);
    };

    this.registerDomEvent(doc, "keyup", handleCursorMove);
    this.registerDomEvent(doc, "pointerup", handleCursorMove);

    // 2-second background live pulse
    this.livePulseIntervalID = window.setInterval(async () => {
      await this.runLivePulse();
    }, 2000);
    this.registerInterval(this.livePulseIntervalID);
  }

  async runLivePulse() {
    if (this.isSyncing || this.isFastSyncing) return;
    if (document.visibilityState !== "visible") return;
    if (!this.settings.cloudsync?.token || !this.settings.cloudsync?.vaultId) return;

    const { fsRemote, profileID } = this.getOrCreateClients();

    try {
      const changesRes = await fsRemote.getChanges(this.lastKnownRevision);
      if (!changesRes || !changesRes.ok) return;

      if (changesRes.fullScanNeeded) {
        console.info("CloudSync: Remote changes exceeded buffer, triggering full sync");
        await this.syncRun("auto");
        return;
      }

      if (changesRes.changes && changesRes.changes.length > 0) {
        console.info(`CloudSync: Received ${changesRes.changes.length} remote change(s)`);
        await this.runFastPull(changesRes.changes);
      }

      if (changesRes.revision > this.lastKnownRevision) {
        this.lastKnownRevision = changesRes.revision;
        await saveLatestVaultRevision(
          this.db,
          this.vaultRandomID,
          profileID,
          this.lastKnownRevision
        );
      }
    } catch {
      // Background pulse fails silently on transient network blips
    }
  }

  applyRemoteCursor(path: string, cursor: { line: number; ch: number }) {
    const leaves = this.app.workspace.getLeavesOfType("markdown");
    const matchingLeaf = leaves.find(
      (l: any) => (l.view as any).file?.path === path
    );
    if (matchingLeaf && (matchingLeaf.view as any).editor) {
      this.isApplyingRemoteCursor = true;
      const editor = (matchingLeaf.view as any).editor;
      window.setTimeout(() => {
        try {
          editor.setCursor(cursor);
          editor.scrollIntoView({ from: cursor, to: cursor });
        } catch {}
        window.setTimeout(() => {
          this.isApplyingRemoteCursor = false;
        }, 500);
      }, 50);
    }
  }

  async sendCursorUpdate(path: string, cursor: { line: number; ch: number }) {
    if (this.isSyncing || this.isFastSyncing || this.isApplyingRemoteCursor) return;
    if (!this.settings.cloudsync?.token || !this.settings.cloudsync?.vaultId) return;

    const { fsRemote, fsEncrypt } = this.getOrCreateClients();
    try {
      await fsEncrypt.updateCursor(path, cursor);
      if (fsRemote.latestRevision && fsRemote.latestRevision > this.lastKnownRevision) {
        this.lastKnownRevision = fsRemote.latestRevision;
      }
    } catch {
      // Ephemeral cursor update silently ignores network errors
    }
  }

  async runFastPull(changes: VaultChangeItem[]) {
    if (this.isSyncing || this.isFastSyncing) return;
    this.isFastSyncing = true;
    const { fsLocal, fsEncrypt, profileID } = this.getOrCreateClients();

    try {
      if (this.statusBarElement) {
        this.statusBarElement.setText("CloudSync: Pulling...");
      }

      let pulled = 0;
      let deleted = 0;
      for (const ch of changes) {
        const plainKey = await fsEncrypt.decryptRemoteKey(ch.key);
        if (ch.action !== "cursor") {
          this.suppressLocalEvents.add(plainKey);
        }

        try {
          const res = await fastPullChange(
            ch,
            fsLocal,
            fsEncrypt,
            this.db,
            this.vaultRandomID,
            profileID,
            this.settings,
            this.app.vault.configDir
          );
          if (res.action === "pulled") pulled++;
          if (res.action === "deleted") deleted++;

          if (res.cursor) {
            this.applyRemoteCursor(plainKey, res.cursor);
          }
        } finally {
          if (ch.action !== "cursor") {
            window.setTimeout(() => {
              this.suppressLocalEvents.delete(plainKey);
            }, 800);
          }
        }
      }

      if (this.statusBarElement) {
        this.statusBarElement.setText("CloudSync: Synced");
      }
      if (pulled > 0 || deleted > 0) {
        this.addSyncLog({
          type: "info",
          message: `Live sync: ${pulled} updated, ${deleted} deleted`,
        });
        if (this.settings.showSyncNotifications) {
          new Notice(`CloudSync: Synced (${pulled} updated, ${deleted} deleted)`, 2000);
        }
      }
    } catch (err: any) {
      console.error("CloudSync: Fast pull error, falling back to full sync:", err);
      await this.syncRun("auto");
    } finally {
      this.isFastSyncing = false;
    }
  }

  shouldIgnorePath(path: string): boolean {
    if (this.suppressLocalEvents.has(path)) return true;
    if (path.startsWith(DEFAULT_DEBUG_FOLDER)) return true;
    if (path.startsWith(DEFAULT_DEVICE_CONFIGS_FOLDER)) return true;

    const isNotesOnly =
      (this.settings.settingsSyncMode ?? "notes_only") !== "shared";
    if (
      isNotesOnly &&
      (path.startsWith(`${this.app.vault.configDir}/`) ||
        path === this.app.vault.configDir)
    ) {
      return true;
    }

    if (isHiddenPath(path, true, false)) return true;
    if (!this.settings.syncUnderscoreItems && isHiddenPath(path, false, true)) return true;
    if (isSpecialFolderNameToSkip(path, this.settings.ignorePaths ?? [])) return true;
    return false;
  }

  onVaultModified(path: string) {
    if (this.isSyncing || this.isFastSyncing) return;
    if (!this.settings.cloudsync?.token || !this.settings.cloudsync?.vaultId) return;
    if (this.shouldIgnorePath(path)) return;

    // Capture cursor for active note
    const leaves = this.app.workspace.getLeavesOfType("markdown");
    const activeLeaf = leaves.find(
      (l: any) => (l.view as any).file?.path === path
    );
    if (activeLeaf && (activeLeaf.view as any).editor) {
      const cur = (activeLeaf.view as any).editor.getCursor();
      this.lastLocalCursor = { path, line: cur.line, ch: cur.ch };
    }

    this.pendingModifiedPaths.add(path);
    this.hasPendingSyncOnSave = true;

    if (this.debouncePushTimer) {
      window.clearTimeout(this.debouncePushTimer);
    }
    this.debouncePushTimer = window.setTimeout(async () => {
      await this.triggerDebouncedPush();
    }, 800);
  }

  async triggerDebouncedPush() {
    if (this.isSyncing || this.isFastSyncing) return;
    if (this.pendingModifiedPaths.size === 0) return;

    const pathsToSync = Array.from(this.pendingModifiedPaths);
    this.pendingModifiedPaths.clear();
    this.hasPendingSyncOnSave = false;

    if (pathsToSync.length > 5) {
      await this.syncRun("auto_sync_on_save");
      return;
    }

    await this.runFastPush(pathsToSync);
  }

  async runFastPush(paths: string[]) {
    if (this.isSyncing || this.isFastSyncing) return;
    this.isFastSyncing = true;
    const { fsLocal, fsRemote, fsEncrypt, profileID } = this.getOrCreateClients();

    try {
      if (this.statusBarElement) {
        this.statusBarElement.setText("CloudSync: Syncing...");
      }

      for (const p of paths) {
        const cursor =
          this.lastLocalCursor && this.lastLocalCursor.path === p
            ? { line: this.lastLocalCursor.line, ch: this.lastLocalCursor.ch }
            : undefined;

        await fastPushPath(
          p,
          fsLocal,
          fsEncrypt,
          this.db,
          this.vaultRandomID,
          profileID,
          this.settings,
          cursor
        );
        this.addSyncLog({
          type: "success",
          message: `Uploaded ${p}`,
          file: p,
        });
      }

      if (fsRemote.latestRevision && fsRemote.latestRevision > this.lastKnownRevision) {
        this.lastKnownRevision = fsRemote.latestRevision;
        await saveLatestVaultRevision(
          this.db,
          this.vaultRandomID,
          profileID,
          this.lastKnownRevision
        );
      }

      if (this.statusBarElement) {
        this.statusBarElement.setText("CloudSync: Synced");
      }
    } catch (err: any) {
      console.error("CloudSync: Fast push error, falling back to full sync:", err);
      await this.syncRun("auto_sync_on_save");
    } finally {
      this.isFastSyncing = false;
    }
  }

  async loadSettings() {
    this.settings = Object.assign(
      {},
      cloneDeep(DEFAULT_SETTINGS),
      messyConfigToNormal(await this.loadData())
    );

    if (this.settings.cloudsync === undefined) {
      this.settings.cloudsync = cloneDeep(DEFAULT_CLOUDSYNC_CONFIG);
    }

    // Auto-migrate away from smart_conflict: diff3 git markers corrupt notes and crash plugins like Dataview
    if (
      this.settings.conflictAction === "smart_conflict" ||
      !this.settings.conflictAction
    ) {
      this.settings.conflictAction = "keep_newer";
      await this.saveSettings();
    }

    // Auto-initialize device identity and settingsSyncMode
    initDeviceIdentity(this.settings);
  }

  async saveSettings() {
    if (this.settings.obfuscateSettingFile) {
      await this.saveData(normalConfigToMessy(this.settings));
    } else {
      await this.saveData(this.settings);
    }
  }

  getCurrProfileID(): string {
    const user = (
      this.settings.cloudsync?.username ||
      this.settings.cloudsync?.email ||
      this.settings.cloudsync?.userId ||
      ""
    )
      .trim()
      .toLowerCase();
    const vaultId = (this.settings.cloudsync?.vaultId || "").trim();
    if (!user) return "cloudsync-unauth";
    return `cloudsync-${user}-${vaultId || "default"}`;
  }

  getVaultBasePath(): string {
    if (this.app.vault.adapter instanceof FileSystemAdapter) {
      return this.app.vault.adapter.getBasePath();
    }
    return "";
  }

  async getVaultRandomIDFromOldConfigFile(): Promise<string> {
    return "";
  }

  async prepareDBAndVaultRandomID(
    vaultBasePath: string,
    vaultRandomIDFromOldConfigFile: string,
    profileID: string
  ) {
    const res = await prepareDBs(
      vaultBasePath,
      vaultRandomIDFromOldConfigFile,
      profileID
    );
    this.db = res.db;
    this.vaultRandomID = res.vaultRandomID;
  }

  enableAutoSyncIfSet() {
    if (
      this.settings.autoRunEveryMilliseconds !== undefined &&
      this.settings.autoRunEveryMilliseconds > 0
    ) {
      this.autoRunIntervalID = window.setInterval(async () => {
        await this.syncRun("auto");
      }, this.settings.autoRunEveryMilliseconds);
      this.registerInterval(this.autoRunIntervalID);
    }
  }

  enableInitSyncIfSet() {
    if (
      this.settings.initRunAfterMilliseconds !== undefined &&
      this.settings.initRunAfterMilliseconds > 0
    ) {
      window.setTimeout(async () => {
        await this.syncRun("auto_once_init");
      }, this.settings.initRunAfterMilliseconds);
    }
  }

  toggleSyncOnSaveIfSet() {
    if (
      this.settings.syncOnSaveAfterMilliseconds !== undefined &&
      this.settings.syncOnSaveAfterMilliseconds > 0
    ) {
      this.syncOnSaveIntervalID = window.setInterval(async () => {
        if (this.hasPendingSyncOnSave) {
          this.hasPendingSyncOnSave = false;
          await this.syncRun("auto_sync_on_save");
        }
      }, this.settings.syncOnSaveAfterMilliseconds);
      this.registerInterval(this.syncOnSaveIntervalID);
    }
  }

  enableCheckingFileStat() {
    this.registerEvent(
      this.app.vault.on("modify", (file) => {
        this.onVaultModified(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("create", (file) => {
        this.onVaultModified(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("delete", (file) => {
        this.onVaultModified(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("rename", (file, oldPath) => {
        this.onVaultModified(oldPath);
        this.onVaultModified(file.path);
      })
    );
  }

  setCurrSyncMsg(
    t: any,
    s: SyncTriggerSourceType,
    counter: number,
    total: number,
    path: string,
    decision: string,
    triggerSource: SyncTriggerSourceType
  ) {
    this.currSyncMsg = `Syncing (${counter}/${total}): ${path}`;
    if (this.statusBarElement) {
      this.statusBarElement.setText(`CloudSync: ${counter}/${total}`);
    }
  }
}
