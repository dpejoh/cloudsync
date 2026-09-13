import cloneDeep from "lodash/cloneDeep";
import throttle from "lodash/throttle";
import { FileText, RefreshCcw, RotateCcw, createElement } from "lucide";
import {
  Events,
  FileSystemAdapter,
  Notice,
  Platform,
  Plugin,
  TFolder,
  addIcon,
  setIcon,
} from "obsidian";
import type {
  CloudSyncConfig,
  RemotelySavePluginSettings,
  SyncTriggerSourceType,
} from "./baseTypes";
import {
  COMMAND_URI,
  DEFAULT_CLOUDSYNC_CONFIG,
  DEFAULT_DEBUG_FOLDER,
} from "./baseTypes";
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
  conflictAction: "smart_conflict",
  protectModifyPercentage: 50,
  syncDirection: "bidirectional",
  obfuscateSettingFile: true,
  enableMobileStatusBar: true,
  encryptionMethod: "rclone-base64",
  profiler: DEFAULT_PROFILER_CONFIG,
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

  getOrCreateClients() {
    const vaultName = this.app.vault.getName();
    const profileID = this.getCurrProfileID();

    if (!this.cachedFsLocal) {
      this.cachedFsLocal = new FakeFsLocal(
        this.app.vault,
        this.settings.syncConfigDir ?? false,
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

  async syncRun(triggerSource: SyncTriggerSourceType = "manual") {
    const t = (x: TransItemType, vars?: any) => {
      return this.i18n.t(x, vars);
    };

    if (!this.settings.cloudsync.token) {
      new Notice("CloudSync: Please log in via settings to start syncing.");
      return;
    }

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
    }

    // Commands
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

    // Add settings tab
    this.addSettingTab(new CloudSyncSettingTab(this.app, this));

    // Enable file stat checking for real-time sync-on-save
    this.enableCheckingFileStat();

    // Initialize real-time live pulse and change tracking
    await this.initRealtimeSync(profileID);

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

    // 2-second background live pulse
    this.livePulseIntervalID = window.setInterval(async () => {
      await this.runLivePulse();
    }, 2000);
    this.registerInterval(this.livePulseIntervalID);
  }

  async runLivePulse() {
    if (this.isSyncing || this.isFastSyncing) return;
    if (document.visibilityState !== "visible") return;
    if (!this.settings.cloudsync?.token) return;

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
        this.suppressLocalEvents.add(plainKey);

        try {
          const res = await fastPullChange(
            ch,
            fsLocal,
            fsEncrypt,
            this.db,
            this.vaultRandomID,
            profileID
          );
          if (res.action === "pulled") pulled++;
          if (res.action === "deleted") deleted++;
        } finally {
          window.setTimeout(() => {
            this.suppressLocalEvents.delete(plainKey);
          }, 800);
        }
      }

      if (this.statusBarElement) {
        this.statusBarElement.setText("CloudSync: Synced");
      }
      if (pulled > 0 || deleted > 0) {
        new Notice(`CloudSync: Synced (${pulled} updated, ${deleted} deleted)`, 2000);
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
    if (isHiddenPath(path, true, false)) return true;
    if (!this.settings.syncUnderscoreItems && isHiddenPath(path, false, true)) return true;
    if (isSpecialFolderNameToSkip(path, this.settings.ignorePaths ?? [])) return true;
    return false;
  }

  onVaultModified(path: string) {
    if (this.isSyncing || this.isFastSyncing) return;
    if (this.shouldIgnorePath(path)) return;

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
        await fastPushPath(
          p,
          fsLocal,
          fsEncrypt,
          this.db,
          this.vaultRandomID,
          profileID,
          this.settings
        );
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
  }

  async saveSettings() {
    if (this.settings.obfuscateSettingFile) {
      await this.saveData(normalConfigToMessy(this.settings));
    } else {
      await this.saveData(this.settings);
    }
  }

  getCurrProfileID(): string {
    const email = (this.settings.cloudsync?.email || "").trim().toLowerCase();
    const vaultId = (this.settings.cloudsync?.vaultId || "").trim();
    if (!email) return "cloudsync-unauth";
    return `cloudsync-${email}-${vaultId || "default"}`;
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
