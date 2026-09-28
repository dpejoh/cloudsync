import cloneDeep from "lodash/cloneDeep";
import throttle from "lodash/throttle";
import { FileText, RefreshCcw, RotateCcw, createElement } from "lucide";
import {
  Events,
  FileSystemAdapter,
  Menu,
  Notice,
  Platform,
  MarkdownView,
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
import {
  COMMAND_URI,
  DEFAULT_CLOUDSYNC_CONFIG,
  DEFAULT_DEBUG_FOLDER,
  DEFAULT_DEVICE_CONFIGS_FOLDER,
} from "./baseTypes";
import { messyConfigToNormal, normalConfigToMessy } from "./configPersist";
import { vaultKeyToPassword } from "./cryptoV2";
import { exportVaultSyncPlansToFiles } from "./debugMode";
import { DeletedFilesModal } from "./deletedFilesModal";
import {
  backupDeviceSettings,
  initDeviceIdentity,
  restoreDeviceSettings,
} from "./deviceSettings";
import { fastPullChange, fastPushPath } from "./fastSync";
import { FakeFsEncrypt } from "./fsEncrypt";
import { getClient } from "./fsGetter";
import { FakeFsLocal } from "./fsLocal";
import { FakeFsWorker, type VaultChangeItem } from "./fsWorker";
import { I18n } from "./i18n";
import type { LangTypeAndAuto, TransItemType } from "./i18n";
import { importQrCodeUri } from "./importExport";
import { AccountKeyManager } from "./keyManager";
import {
  type InternalDBs,
  clearAllLoggerOutputRecords,
  clearExpiredSyncPlanRecords,
  destroyDBs,
  getLastFailedSyncTimeByVault,
  getLastSuccessSyncTimeByVault,
  getLatestVaultRevision,
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
import { PresenceManager } from "./presenceManager";
import { DEFAULT_PROFILER_CONFIG, Profiler } from "./profiler";
import { runVaultRekey } from "./rotationUi";
import { CloudSyncSettingTab } from "./settings";
import { syncer } from "./sync";
import type { SyncLogEntry } from "./syncLogModal";
import { SyncLogModal } from "./syncLogModal";
import { VaultPickerModal } from "./vaultPickerModal";
import { VersionHistoryModal } from "./versionHistoryModal";

const DEFAULT_SETTINGS: RemotelySavePluginSettings = {
  cloudsync: DEFAULT_CLOUDSYNC_CONFIG,
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
  safetyDeletionThreshold: 25,
  syncDirection: "bidirectional",
  obfuscateSettingFile: false,
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
  cachedFsLocalSyncConfigDir?: boolean;
  cachedFsLocalDeleteToWhere?: string;

  cachedFsRemote?: FakeFsWorker;
  cachedRemoteVaultId?: string;
  cachedRemoteServerUrl?: string;
  cachedRemoteToken?: string;
  cachedRemoteOwner?: string;

  cachedFsEncrypt?: FakeFsEncrypt;
  cachedFsEncryptPassword?: string;
  cachedFsEncryptMethod?: string;

  keyManager!: AccountKeyManager;

  debouncePushTimer?: number;
  pendingModifiedPaths: Set<string> = new Set<string>();
  pendingDeletedPaths: Set<string> = new Set<string>();
  suppressLocalEvents: Set<string> = new Set<string>();
  livePulseIntervalID?: number;
  livePulseTimeoutID?: number;
  lastUserActivityTime = Date.now();
  private lastDeviceHeartbeat = 0;
  isFastSyncing = false;
  lastKnownRevision = 0;

  presenceManager!: PresenceManager;
  settingTab?: CloudSyncSettingTab;
  lastLocalCursor: { path: string; line: number; ch: number } | null = null;

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

  clearCachedClients() {
    if (this.cachedFsEncrypt) {
      try {
        this.cachedFsEncrypt.closeResources();
      } catch {}
    }
    this.cachedFsLocal = undefined;
    this.cachedFsLocalSyncConfigDir = undefined;
    this.cachedFsLocalDeleteToWhere = undefined;

    this.cachedFsRemote = undefined;
    this.cachedRemoteVaultId = undefined;
    this.cachedRemoteServerUrl = undefined;
    this.cachedRemoteToken = undefined;
    this.cachedRemoteOwner = undefined;

    this.cachedFsEncrypt = undefined;
    this.cachedFsEncryptPassword = undefined;
    this.cachedFsEncryptMethod = undefined;
  }

  isUnlockedForSync(): boolean {
    return (
      this.settings.cloudsync?.scheme === 2 && !!this.keyManager?.isUnlocked
    );
  }

  async getOrCreateClients() {
    const vaultName = this.app.vault.getName();
    const profileID = this.getCurrProfileID();
    const cs = this.settings.cloudsync;

    const syncConfigDir =
      (this.settings.settingsSyncMode ?? "notes_only") === "shared";
    const deleteToWhere = this.settings.deleteToWhere ?? "system";

    if (
      this.cachedFsLocal &&
      (this.cachedFsLocalSyncConfigDir !== syncConfigDir ||
        this.cachedFsLocalDeleteToWhere !== deleteToWhere)
    ) {
      this.cachedFsLocal = undefined;
    }

    if (!this.cachedFsLocal) {
      this.cachedFsLocalSyncConfigDir = syncConfigDir;
      this.cachedFsLocalDeleteToWhere = deleteToWhere;
      this.cachedFsLocal = new FakeFsLocal(
        this.app.vault,
        syncConfigDir,
        this.settings.syncBookmarks ?? false,
        this.app.vault.configDir,
        this.manifest.id,
        undefined,
        deleteToWhere
      );
    }

    if (
      this.cachedFsRemote &&
      (this.cachedRemoteVaultId !== cs.vaultId ||
        this.cachedRemoteServerUrl !== cs.serverUrl ||
        this.cachedRemoteToken !== cs.token ||
        this.cachedRemoteOwner !== cs.vaultOwner)
    ) {
      this.cachedFsRemote = undefined;
      if (this.cachedFsEncrypt) {
        try {
          this.cachedFsEncrypt.closeResources();
        } catch {}
        this.cachedFsEncrypt = undefined;
      }
    }

    if (!this.cachedFsRemote) {
      this.cachedRemoteVaultId = cs.vaultId;
      this.cachedRemoteServerUrl = cs.serverUrl;
      this.cachedRemoteToken = cs.token;
      this.cachedRemoteOwner = cs.vaultOwner;
      this.cachedFsRemote = new FakeFsWorker(
        {
          ...cs,
          deviceId: this.settings.deviceId,
          deviceName: this.settings.deviceName,
        },
        vaultName
      );
    }

    // Each vault has its own random key, delivered through the account key
    // material (owned vaults) or an owner-issued envelope (shared vaults).
    // Callers must check `isUnlockedForSync()` first; when locked we fall back
    // to an empty password so nothing is ever written unencrypted.
    let effectivePassword = "";
    let integrityKey: Uint8Array | undefined;
    if (cs.scheme === 2 && cs.vaultId && this.keyManager?.isUnlocked) {
      const isSharedVault =
        !!cs.vaultOwner &&
        cs.vaultOwner.toLowerCase() !== (cs.username || "").toLowerCase();
      let vaultKey = await this.keyManager.getVaultKey(cs.vaultId);
      if (!vaultKey && isSharedVault) {
        const opened = await this.keyManager.fetchSharedVaultKey({
          vaultId: cs.vaultId,
          ownerUsername: cs.vaultOwner!,
        });
        if (opened) vaultKey = opened.vk;
      }
      if (!vaultKey && !isSharedVault) {
        const remoteFiles = await this.cachedFsRemote.walk();
        const hasExistingData = remoteFiles.some(
          (entity) =>
            !entity.keyRaw.startsWith(".cloudsync") &&
            !entity.keyRaw.startsWith("_device_configs")
        );
        if (hasExistingData) {
          throw new Error(
            "This vault was created with an older version of CloudSync. Create a new remote vault instead."
          );
        }
        vaultKey = await this.keyManager.ensureOwnedVaultKey(cs.vaultId);
      }
      if (!vaultKey) {
        throw new Error(
          "The owner has not shared the vault key with your account yet."
        );
      }
      effectivePassword = vaultKeyToPassword(vaultKey);
      integrityKey =
        (await this.keyManager.integrityKey(cs.vaultId)) ?? undefined;
    }
    this.cachedFsRemote?.setIntegrityKey(integrityKey);
    this.cachedFsRemote?.setKeyVersion(
      cs.vaultId ? this.keyManager?.vaultKeyVersion(cs.vaultId) : undefined
    );

    if (
      !this.cachedFsEncrypt ||
      this.cachedFsEncryptPassword !== effectivePassword ||
      this.cachedFsEncryptMethod !== this.settings.encryptionMethod
    ) {
      if (this.cachedFsEncrypt) {
        try {
          this.cachedFsEncrypt.closeResources();
        } catch {}
      }
      this.cachedFsEncryptPassword = effectivePassword;
      this.cachedFsEncryptMethod =
        this.settings.encryptionMethod || "rclone-base64";
      this.cachedFsEncrypt = new FakeFsEncrypt(
        this.cachedFsRemote,
        effectivePassword,
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

  async autoRegisterDevice(force = false) {
    if (!this.settings.cloudsync?.token) return;
    if (!this.isUnlockedForSync()) return;
    const now = Date.now();
    if (!force && now - this.lastDeviceHeartbeat < 6 * 3600 * 1000) {
      return;
    }
    this.lastDeviceHeartbeat = now;

    initDeviceIdentity(this.settings);
    const { fsRemote } = await this.getOrCreateClients();
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
      } else if (res.status === 401) {
        await this.markSessionExpired();
      }
    } catch {}
  }

  /**
   * The server rejected the stored token. Keep the token (so the derived profileID
   * and local prev-sync records survive) but flag the session so the settings UI
   * shows the login screen instead of pretending to be signed in.
   */
  async markSessionExpired() {
    const cs = this.settings.cloudsync;
    if (!cs?.token || cs.sessionExpired) return;
    cs.sessionExpired = true;
    await this.saveSettings();
    // Deferred so we never re-render the settings tab in the middle of an
    // in-flight render that detected the 401.
    window.setTimeout(() => {
      this.settingTab?.display().catch(() => {});
    }, 0);
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
            this.settings.isSyncPaused ? "Sync paused" : "Sync resumed"
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

    menu.addItem((item) => {
      item
        .setTitle("Dry run (Preview changes)")
        .setIcon("lucide-eye")
        .setDisabled(!hasVault)
        .onClick(async () => {
          await this.syncRun("dry");
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

    // Don't spam 401 notices on background syncs after the session expired.
    if (this.settings.cloudsync.sessionExpired && triggerSource !== "manual") {
      return;
    }

    if (!this.settings.cloudsync.token) {
      new Notice("Please log in to start syncing.");
      return;
    }

    if (!this.settings.cloudsync.vaultId) {
      new Notice("Please choose a remote vault to start syncing.");
      return;
    }

    if (!this.isUnlockedForSync()) {
      new Notice("CloudSync is locked. Please sign in again.");
      return;
    }

    this.addSyncLog({
      type: "info",
      message: `Sync started (${triggerSource})`,
    });

    const { fsLocal, fsRemote, fsEncrypt, profileID } =
      await this.getOrCreateClients();

    const markIsSyncingFunc = (status: boolean) => {
      this.isSyncing = status;
      if (!status) {
        this.currSyncMsg = "";
      }
    };

    const notifyFunc = async (s: SyncTriggerSourceType, step: number) => {
      if (s === "manual" && step === 0) {
        new Notice("Starting sync...");
      }
    };

    const errNotifyFunc = async (s: SyncTriggerSourceType, err: any) => {
      const errMsg = err?.message || `${err}`;
      const isAuthError = errMsg.includes("401") || errMsg.includes("Unauthorized");
      if (isAuthError) {
        await this.markSessionExpired().catch(() => {});
      }
      this.addSyncLog({
        type: "error",
        message: isAuthError
          ? "CloudSync session expired. Please log in again from Settings."
          : `Sync error: ${errMsg}`,
      });
      new Notice(
        isAuthError
          ? "CloudSync session expired. Please log in again from Settings."
          : `Sync error: ${errMsg}`,
        isAuthError ? 8000 : 5000
      );
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
          this.statusBarElement.setText("Syncing...");
        } else if (everythingOk) {
          this.statusBarElement.setText("Synced");
        } else {
          this.statusBarElement.setText("Sync failed");
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

    if (this.isSyncing || this.isFastSyncing) {
      if (triggerSource === "manual") {
        new Notice("Sync is already running.");
      }
      return;
    }

    if (
      (triggerSource === "auto" || triggerSource === "auto_sync_on_save") &&
      this.lastKnownRevision > 0 &&
      fsRemote instanceof FakeFsWorker
    ) {
      try {
        const changesRes = await fsRemote.getChanges(this.lastKnownRevision);
        if (changesRes && changesRes.ok && !changesRes.fullScanNeeded) {
          if (changesRes.changes && changesRes.changes.length > 0) {
            await this.runFastPull(changesRes.changes);
          }
          if (this.pendingModifiedPaths.size > 0) {
            const pathsToSync = Array.from(this.pendingModifiedPaths);
            this.pendingModifiedPaths.clear();
            this.hasPendingSyncOnSave = false;
            await this.runFastPush(pathsToSync);
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
          return;
        }
      } catch (err) {
        console.warn("CloudSync: Fast sync check failed, falling back to full sync", err);
      }
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
      new Notice(`Sync failed: ${err?.message || err}`);
    } finally {
      // A full sync reconciles the entire vault, so the revision observed by the
      // last full walk is safe to persist. Write-response revisions are not used
      // because they can be newer than a concurrent remote change we never saw.
      const walkRev = this.cachedFsRemote?.latestWalkRevision;
      if (walkRev && walkRev > this.lastKnownRevision) {
        this.lastKnownRevision = walkRev;
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
      clearExpiredSyncPlanRecords(this.db).catch(() => {});
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

    this.keyManager = new AccountKeyManager({
      transport: {
        request: async (path, opts) => {
          const base = (this.settings.cloudsync.serverUrl || "").replace(
            /\/+$/,
            ""
          );
          const headers: Record<string, string> = { ...(opts?.headers ?? {}) };
          if (opts?.token) headers.Authorization = `Bearer ${opts.token}`;
          let body: string | undefined;
          if (opts?.body !== undefined) {
            headers["content-type"] = "application/json";
            body = JSON.stringify(opts.body);
          }
          const res = await requestUrl({
            url: `${base}${path}`,
            method: opts?.method ?? "GET",
            headers,
            body,
            throw: false,
          });
          return {
            status: res.status,
            json: res.json,
            text: res.text,
            headers: res.headers,
            arrayBuffer: res.arrayBuffer,
          };
        },
      },
      config: this.settings.cloudsync,
      persist: async () => {
        await this.saveSettings();
      },
    });
    await this.keyManager.unlockFromCache().catch(() => {});

    const profileID: string = this.getCurrProfileID();

    this.i18n = new I18n(this.settings.lang!, async (lang: LangTypeAndAuto) => {
      this.settings.lang = lang;
      await this.saveSettings();
    });

    const vaultBasePath = this.getVaultBasePath();
    const vaultRandomIDFromOld = await this.getVaultRandomIDFromOldConfigFile();

    const csAtLoad = this.settings.cloudsync;
    const accountChanged =
      !!csAtLoad?.token &&
      (csAtLoad.lastConnectedUserId !== csAtLoad.userId ||
        csAtLoad.lastConnectedVaultId !== csAtLoad.vaultId);
    if (!csAtLoad?.token || accountChanged) {
      try {
        await destroyDBs();
        if (accountChanged) {
          console.warn(
            "CloudSync: account/vault changed; local sync database was reset to avoid stale comparisons."
          );
        }
      } catch (e) {
        console.warn("Clean state db destroy skipped:", e);
      }
    }
    if (csAtLoad?.token) {
      csAtLoad.lastConnectedUserId = csAtLoad.userId;
      csAtLoad.lastConnectedVaultId = csAtLoad.vaultId;
      await this.saveSettings();
    }

    await this.prepareDBAndVaultRandomID(
      vaultBasePath,
      vaultRandomIDFromOld,
      profileID
    );

    this.registerObsidianProtocolHandler(COMMAND_URI, async (inputParams) => {
      const parsed = importQrCodeUri(inputParams, this.app.vault.getName());
      if (parsed.status === "error" || parsed.result === undefined) {
        new Notice(parsed.message);
        return;
      }

      const imported = parsed.result;
      const importedUrl = imported.cloudsync?.serverUrl ?? "";
      if (importedUrl && !/^https?:\/\//i.test(importedUrl)) {
        new Notice("Imported settings rejected: invalid server URL.");
        return;
      }
      if (!confirm(
        `Import settings from this link?\n\n` +
          `Server: ${importedUrl || "(none)"}\n` +
          `Account: ${imported.cloudsync?.username || "(none)"}\n\n` +
          `This will replace your sync configuration and may sign you in to the server above.`,
      )) {
        return;
      }

      this.settings = Object.assign({}, this.settings, imported);
      await this.saveSettings();
      new Notice("Settings imported.");
    });

    this.syncRibbon = this.addRibbonIcon(
      iconNameSyncWait,
      "Sync vault",
      async () => this.syncRun("manual")
    );

    if (this.settings.enableStatusBarInfo) {
      const statusBarItem = this.addStatusBarItem();
      this.statusBarElement = statusBarItem.createEl("span");
      this.statusBarElement.setText("Ready");
      this.statusBarElement.addClass("mod-clickable");
      statusBarItem.addClass("mod-clickable");
      statusBarItem.addEventListener("click", (evt) => {
        this.openStatusIconMenu(evt);
      });
    }

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

    this.addCommand({
      id: "version-history",
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
      id: "choose-vault",
      name: "Choose remote vault",
      icon: "lucide-folder-sync",
      callback: () => {
        new VaultPickerModal(this.app, this).open();
      },
    });

    this.addCommand({
      id: "sync-now",
      name: "Sync Vault Now",
      icon: iconNameSyncWait,
      callback: async () => {
        await this.syncRun("manual");
      },
    });

    this.addCommand({
      id: "dry-run",
      name: "Dry Run (Preview Changes)",
      icon: iconNameSyncWait,
      callback: async () => {
        await this.syncRun("dry");
      },
    });

    this.addCommand({
      id: "backup-device-settings",
      name: "Backup Settings for This Device to Cloud",
      callback: async () => {
        if (!this.isUnlockedForSync()) {
          new Notice("CloudSync is locked. Please sign in again.");
          return;
        }
        const { fsEncrypt, fsRemote } = await this.getOrCreateClients();
        const notice = new Notice("Backing up device settings...", 0);
        try {
          const res = await backupDeviceSettings(
            this.app,
            fsEncrypt,
            fsRemote as FakeFsWorker,
            this.settings,
            (msg) => notice.setMessage(msg)
          );
          await this.saveSettings();
          notice.hide();
          new Notice(`Backed up ${res.fileCount} settings files.`);
        } catch (err: any) {
          notice.hide();
          new Notice(`Failed to back up settings: ${err?.message || err}`);
        }
      },
    });

    this.addCommand({
      id: "deleted-files",
      name: "Open Cloud Trash (Restore Deleted Files)",
      icon: "lucide-trash-2",
      callback: () => {
        new DeletedFilesModal(this.app, this, false).open();
      },
    });

    this.addCommand({
      id: "sync-log",
      name: "Open Sync Activity Log",
      icon: "lucide-align-left",
      callback: () => {
        new SyncLogModal(this.app, this).open();
      },
    });

    this.settingTab = new CloudSyncSettingTab(this.app, this);
    this.addSettingTab(this.settingTab);

    this.enableCheckingFileStat();

    await this.initRealtimeSync(profileID);

    await this.autoRegisterDevice();

    this.presenceManager = new PresenceManager(this);
    this.registerEditorExtension(this.presenceManager.getEditorExtensions());
    this.registerEvent(
      this.app.workspace.on("active-leaf-change", (leaf) => {
        const view = leaf?.view;
        if (!view || !(view instanceof MarkdownView) || !view.file) {
          if (this.presenceManager) {
            this.presenceManager.handleLocalLeave();
          }
        } else {
          this.presenceManager.dispatchPresencesToOpenLeaves();
        }
      })
    );

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
    if (this.presenceManager) {
      this.presenceManager.destroy();
    }
    if (this.autoRunIntervalID) {
      window.clearInterval(this.autoRunIntervalID);
    }
    if (this.livePulseIntervalID) {
      window.clearInterval(this.livePulseIntervalID);
    }
    if (this.livePulseTimeoutID) {
      window.clearTimeout(this.livePulseTimeoutID);
      this.livePulseTimeoutID = undefined;
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
    this.keyManager?.clearSecrets();
  }

  scheduleNextLivePulse(immediate = false) {
    if (this.livePulseTimeoutID) {
      window.clearTimeout(this.livePulseTimeoutID);
      this.livePulseTimeoutID = undefined;
    }

    if (!this.settings.cloudsync?.token || !this.settings.cloudsync?.vaultId) {
      return;
    }

    if (immediate) {
      this.runLivePulse().finally(() => this.scheduleNextLivePulse());
      return;
    }

    // Pause polling while offline or app is hidden/minimized
    if (
      (typeof navigator !== "undefined" && !navigator.onLine) ||
      (typeof document !== "undefined" && document.visibilityState !== "visible")
    ) {
      return;
    }

    const idleMs = Date.now() - this.lastUserActivityTime;
    const isMobile = Platform.isMobileApp;
    let delay = 2000;
    if (idleMs > 120_000) {
      delay = isMobile ? 12000 : 8000;
    } else if (idleMs > 30_000) {
      delay = isMobile ? 6000 : 4000;
    } else {
      delay = isMobile ? 3000 : 2000;
    }

    this.livePulseTimeoutID = window.setTimeout(async () => {
      await this.runLivePulse();
      this.scheduleNextLivePulse();
    }, delay);
  }

  async initRealtimeSync(profileID: string) {
    this.lastKnownRevision = await getLatestVaultRevision(
      this.db,
      this.vaultRandomID,
      profileID
    );

    const wakeSync = () => {
      const now = Date.now();
      const wasAsleep =
        now - this.lastUserActivityTime > 120_000 || !this.livePulseTimeoutID;
      this.lastUserActivityTime = now;
      if (wasAsleep) {
        this.scheduleNextLivePulse(true);
      }
    };

    let lastMove = 0;
    const onMouseMove = () => {
      const now = Date.now();
      if (now - lastMove > 1000) {
        lastMove = now;
        wakeSync();
      }
    };

    this.registerDomEvent(document, "visibilitychange", async () => {
      if (document.visibilityState === "visible") {
        this.lastUserActivityTime = Date.now();
        this.scheduleNextLivePulse(true);
      }
    });

    this.registerDomEvent(window, "focus", () => {
      this.lastUserActivityTime = Date.now();
      this.scheduleNextLivePulse(true);
    });

    this.registerDomEvent(window, "online", () => {
      this.lastUserActivityTime = Date.now();
      this.scheduleNextLivePulse(true);
      if (this.pendingModifiedPaths.size > 0) {
        this.triggerDebouncedPush().catch(() => {});
      }
    });

    this.registerDomEvent(window, "offline", () => {
      if (this.livePulseTimeoutID) {
        window.clearTimeout(this.livePulseTimeoutID);
        this.livePulseTimeoutID = undefined;
      }
    });

    const doc = typeof activeDocument !== "undefined" ? activeDocument : window.document;
    const handleCursorMove = () => {
      wakeSync();
      if (this.isSyncing || this.isFastSyncing) {
        return;
      }
      const activeView = this.app.workspace.activeLeaf?.view as any;
      if (!activeView || !activeView.file || !activeView.editor) return;

      const cur = activeView.editor.getCursor();
      const path = activeView.file.path;
      if (this.shouldIgnorePath(path)) return;

      if (this.presenceManager) {
        this.presenceManager.handleLocalCursor(path, cur);
      }
    };

    this.registerDomEvent(doc, "keydown", wakeSync);
    this.registerDomEvent(doc, "mousedown", wakeSync);
    this.registerDomEvent(doc, "pointerdown", wakeSync);
    this.registerDomEvent(doc, "mousemove", onMouseMove);
    this.registerDomEvent(doc, "scroll", wakeSync);
    this.registerDomEvent(doc, "keyup", handleCursorMove);
    this.registerDomEvent(doc, "pointerup", handleCursorMove);

    const handleWindowLeave = () => {
      if (this.presenceManager) {
        this.presenceManager.sendLeaveSignal();
      }
    };
    this.registerDomEvent(window, "beforeunload", handleWindowLeave);
    this.registerDomEvent(window, "pagehide", handleWindowLeave);

    this.scheduleNextLivePulse();
  }

  async runLivePulse() {
    if (this.isSyncing || this.isFastSyncing) return;
    if (typeof navigator !== "undefined" && !navigator.onLine) return;
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
    } catch (err: any) {
      const errMsg = err?.message || `${err}`;
      if (errMsg.includes("401") || errMsg.includes("Unauthorized")) {
        console.warn("CloudSync: Session expired during live pulse, pausing background pulse.");
        await this.markSessionExpired().catch(() => {});
        if (this.livePulseTimeoutID) {
          window.clearTimeout(this.livePulseTimeoutID);
          this.livePulseTimeoutID = undefined;
        }
      }
    }
  }

  applyRemoteCursor(
    path: string,
    cursor: { line: number; ch: number },
    deviceId?: string,
    deviceName?: string
  ) {
    if (this.presenceManager) {
      this.presenceManager.updateRemotePresence(
        deviceId,
        deviceName,
        path,
        cursor
      );
    }
  }

  removeRemoteCursor(deviceId: string) {
    if (this.presenceManager) {
      this.presenceManager.removeRemotePresence(deviceId);
    }
  }

  async sendCursorUpdate(path: string, cursor: { line: number; ch: number }) {
    if (this.isSyncing || this.isFastSyncing) return;
    if (!this.settings.cloudsync?.token || !this.settings.cloudsync?.vaultId) return;

    const { fsEncrypt } = this.getOrCreateClients();
    try {
      await fsEncrypt.updateCursor(path, cursor);
    } catch {}
  }

  async runFastPull(changes: VaultChangeItem[]) {
    if (this.isSyncing || this.isFastSyncing) return;
    this.isFastSyncing = true;
    const { fsLocal, fsEncrypt, profileID } = this.getOrCreateClients();

    try {
      if (this.statusBarElement) {
        this.statusBarElement.setText("Pulling...");
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
            this.applyRemoteCursor(
              plainKey,
              res.cursor,
              res.deviceId,
              res.deviceName
            );
          } else if (res.action === "cursor" && res.deviceId) {
            this.removeRemoteCursor(res.deviceId);
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
        this.statusBarElement.setText("Synced");
      }
      if (pulled > 0 || deleted > 0) {
        this.addSyncLog({
          type: "info",
          message: `Live sync: ${pulled} updated, ${deleted} deleted`,
        });
        if (this.settings.showSyncNotifications) {
          new Notice(`Synced: ${pulled} updated, ${deleted} deleted`, 2000);
        }
      }
    } catch (err: any) {
      console.error("CloudSync: Fast pull error, falling back to full sync:", err);
      this.isFastSyncing = false;
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

  onVaultModified(path: string, isDeletion = false) {
    this.lastUserActivityTime = Date.now();
    if (this.isSyncing || this.isFastSyncing) return;
    if (!this.settings.cloudsync?.token || !this.settings.cloudsync?.vaultId) return;
    if (this.shouldIgnorePath(path)) return;

    // Only an explicit deletion event may propagate a remote delete. This avoids
    // treating transient stat failures or renamed files as deletions.
    if (isDeletion) {
      this.pendingDeletedPaths.add(path);
    } else {
      this.pendingDeletedPaths.delete(path);
    }

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
    const debounceMs = Platform.isMobileApp ? 1500 : 800;
    this.debouncePushTimer = window.setTimeout(async () => {
      await this.triggerDebouncedPush();
    }, debounceMs);
  }

  async triggerDebouncedPush() {
    if (this.isSyncing || this.isFastSyncing) return;
    if (this.pendingModifiedPaths.size === 0) return;

    const pathsToSync = Array.from(this.pendingModifiedPaths);
    const deletedPaths = new Set(this.pendingDeletedPaths);
    this.pendingModifiedPaths.clear();
    this.pendingDeletedPaths.clear();
    this.hasPendingSyncOnSave = false;

    if (pathsToSync.length > 5) {
      await this.syncRun("auto_sync_on_save");
      return;
    }

    await this.runFastPush(pathsToSync, deletedPaths);
  }

  async runFastPush(paths: string[], deletedPaths: Set<string> = new Set()) {
    if (this.isSyncing || this.isFastSyncing) return;
    this.isFastSyncing = true;
    const { fsLocal, fsRemote, fsEncrypt, profileID } = this.getOrCreateClients();

    try {
      if (this.statusBarElement) {
        this.statusBarElement.setText("Syncing...");
      }

      const failedPaths: string[] = [];
      await Promise.all(
        paths.map(async (p) => {
          const cursor =
            this.lastLocalCursor && this.lastLocalCursor.path === p
              ? { line: this.lastLocalCursor.line, ch: this.lastLocalCursor.ch }
              : undefined;

          try {
            await fastPushPath(
              p,
              fsLocal,
              fsEncrypt,
              this.db,
              this.vaultRandomID,
              profileID,
              this.settings,
              cursor,
              this.app.vault.configDir,
              deletedPaths.has(p)
            );
            this.addSyncLog({
              type: deletedPaths.has(p) ? "info" : "success",
              message: deletedPaths.has(p) ? `Deleted ${p}` : `Uploaded ${p}`,
              file: p,
            });
          } catch (err) {
            console.error(`CloudSync: Fast push failed for ${p}:`, err);
            failedPaths.push(p);
          }
        })
      );

      if (failedPaths.length > 0) {
        for (const fp of failedPaths) {
          this.pendingModifiedPaths.add(fp);
          if (deletedPaths.has(fp)) this.pendingDeletedPaths.add(fp);
        }
      }

      // NOTE: deliberately do not advance lastKnownRevision from write responses.
      // A write's revision can be newer than another device's concurrent change,
      // which would make the next getChanges() call skip that change entirely.

      if (this.statusBarElement) {
        this.statusBarElement.setText(
          failedPaths.length > 0 ? "Retry queued" : "Synced"
        );
      }
    } catch (err: any) {
      console.error("CloudSync: Fast push error, falling back to full sync:", err);
      this.isFastSyncing = false;
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

  /**
   * Wipes the local comparison state so the next sync treats every file as new
   * instead of comparing against records from another account/vault.
   */
  async resetLocalSyncState(): Promise<void> {
    if (this.isSyncing || this.isFastSyncing || this.isRotating) {
      new Notice("Wait for the current operation to finish before resetting.");
      return;
    }
    try {
      if (this.cachedFsEncrypt) {
        try {
          this.cachedFsEncrypt.closeResources();
        } catch {}
      }
      this.clearCachedClients();
      await destroyDBs();
      const vaultBasePath = this.getVaultBasePath();
      await this.prepareDBAndVaultRandomID(
        vaultBasePath,
        await this.getVaultRandomIDFromOldConfigFile(),
        this.getCurrProfileID()
      );
      const cs = this.settings.cloudsync;
      if (cs?.token) {
        cs.lastConnectedUserId = cs.userId;
        cs.lastConnectedVaultId = cs.vaultId;
        await this.saveSettings();
      }
      new Notice(
        "Local sync database reset. The next sync compares everything fresh (nothing is deleted).",
        8000
      );
    } catch (err: any) {
      new Notice(
        `Could not reset the local sync database: ${err?.message || err}`
      );
    }
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
        this.onVaultModified(file.path, true);
      })
    );
    this.registerEvent(
      this.app.vault.on("rename", (file, oldPath) => {
        this.onVaultModified(oldPath, true);
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
      this.statusBarElement.setText(`${counter}/${total}`);
    }
  }
}
