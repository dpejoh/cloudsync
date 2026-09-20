import type { LangTypeAndAuto } from "./i18n";

export const DEFAULT_CONTENT_TYPE = "application/octet-stream";

export type SUPPORTED_SERVICES_TYPE = "cloudsync";

export interface CloudSyncConfig {
  serverUrl: string;
  username: string;
  email?: string; // backwards compatibility
  token: string;
  vaultId: string;
  vaultOwner?: string;
  userId: string;
  mode?: "single" | "multi";
  has2FA?: boolean;
  recoveryKey?: string;
  encryptionKey?: string;
  autoSyncIntervalMinutes?: number;
  syncOnStartup?: boolean;
  syncOnSave?: boolean;
}

export const DEFAULT_CLOUDSYNC_CONFIG: CloudSyncConfig = {
  serverUrl: "",
  username: "",
  email: "",
  token: "",
  vaultId: "",
  vaultOwner: "",
  userId: "",
  mode: "multi",
  encryptionKey: "",
  autoSyncIntervalMinutes: 5,
  syncOnStartup: true,
  syncOnSave: true,
};

export type SyncDirectionType =
  | "bidirectional"
  | "incremental_pull_only"
  | "incremental_push_only"
  | "incremental_pull_and_delete_only"
  | "incremental_push_and_delete_only";

export type CipherMethodType = "rclone-base64" | "openssl-base64" | "unknown";

export type QRExportType = "basic_and_advanced" | SUPPORTED_SERVICES_TYPE;

export interface ProfilerConfig {
  enable?: boolean;
  enablePrinting?: boolean;
  recordSize?: boolean;
}

export interface RemotelySavePluginSettings {
  cloudsync: CloudSyncConfig;
  password: string; // Used as E2EE master key
  serviceType: SUPPORTED_SERVICES_TYPE;
  currLogLevel?: string;
  autoRunEveryMilliseconds?: number;
  initRunAfterMilliseconds?: number;
  syncOnSaveAfterMilliseconds?: number;

  concurrency?: number;
  syncConfigDir?: boolean;
  syncBookmarks?: boolean;
  syncUnderscoreItems?: boolean;
  lang?: LangTypeAndAuto;
  agreeToUseSyncV3?: boolean;
  skipSizeLargerThan?: number;
  ignorePaths?: string[];
  onlyAllowPaths?: string[];
  enableStatusBarInfo?: boolean;
  deleteToWhere?: "system" | "obsidian";
  conflictAction?: ConflictActionType;

  protectModifyPercentage?: number;
  safetyDeletionThreshold?: number;
  syncDirection?: SyncDirectionType;

  obfuscateSettingFile?: boolean;
  enableMobileStatusBar?: boolean;
  encryptionMethod?: CipherMethodType;
  profiler?: ProfilerConfig;

  // Settings sync & device isolation
  settingsSyncMode?: SettingsSyncMode;
  deviceId?: string;
  deviceName?: string;
  lastSettingsBackupTime?: number;

  // File type and configuration sync options
  isSyncPaused?: boolean;
  syncImages?: boolean;
  syncAudio?: boolean;
  syncVideos?: boolean;
  syncPdfs?: boolean;
  syncUnsupported?: boolean;
  syncMainSettings?: boolean;
  syncAppearance?: boolean;
  syncAppearanceData?: boolean;
  syncHotkeys?: boolean;
  syncCorePlugins?: boolean;
  syncCorePluginData?: boolean;
  syncCommunityPlugins?: boolean;
  syncCommunityPluginData?: boolean;
  showSyncNotifications?: boolean;
}

export const COMMAND_URI = "cloudsync";
export const COMMAND_CALLBACK = "cloudsync-cb";

export interface UriParams {
  func?: string;
  vault?: string;
  ver?: string;
  data?: string;
}

export const OAUTH2_FORCE_EXPIRE_MILLISECONDS = 1000 * 60 * 60 * 24 * 80;

export type EmptyFolderCleanType = "skip" | "clean_both";

export type ConflictActionType =
  | "keep_newer"
  | "keep_larger"
  | "smart_conflict";

export type SettingsSyncMode = "notes_only" | "device_isolated" | "shared";

export type DecisionTypeForMixedEntity =
  | "only_history"
  | "equal"
  | "local_is_modified_then_push"
  | "remote_is_modified_then_pull"
  | "local_is_created_then_push"
  | "remote_is_created_then_pull"
  | "local_is_created_too_large_then_do_nothing"
  | "remote_is_created_too_large_then_do_nothing"
  | "local_is_deleted_thus_also_delete_remote"
  | "remote_is_deleted_thus_also_delete_local"
  | "conflict_created_then_keep_local"
  | "conflict_created_then_keep_remote"
  | "conflict_created_then_smart_conflict"
  | "conflict_created_then_do_nothing"
  | "conflict_modified_then_keep_local"
  | "conflict_modified_then_keep_remote"
  | "conflict_modified_then_smart_conflict"
  | "folder_existed_both_then_do_nothing"
  | "folder_existed_local_then_also_create_remote"
  | "folder_existed_remote_then_also_create_local"
  | "folder_to_be_created"
  | "folder_to_skip"
  | "folder_to_be_deleted_on_both"
  | "folder_to_be_deleted_on_remote"
  | "folder_to_be_deleted_on_local";

/**
 * Uniform representation for file/folder entities.
 */
export interface Entity {
  key?: string;
  keyEnc?: string;
  keyRaw: string;
  mtimeCli?: number;
  mtimeCliFmt?: string;
  ctimeCli?: number;
  ctimeCliFmt?: string;
  mtimeSvr?: number;
  mtimeSvrFmt?: string;
  prevSyncTime?: number;
  prevSyncTimeFmt?: string;
  size?: number;
  sizeEnc?: number;
  sizeRaw: number;
  hash?: string;
  etag?: string;
  synthesizedFolder?: boolean;
  synthesizedFile?: boolean;
}

export interface UploadedType {
  entity: Entity;
  mtimeCli?: number;
}

export interface MixedEntity {
  key: string;
  local?: Entity;
  prevSync?: Entity;
  remote?: Entity;

  decisionBranch?: number;
  decision?: DecisionTypeForMixedEntity;
  conflictAction?: ConflictActionType;

  change?: boolean;
  sideNotes?: any;
}

export const DEFAULT_DEBUG_FOLDER = "_debug_cloudsync/";
export const DEFAULT_DEVICE_CONFIGS_FOLDER = "_device_configs/";
export const DEFAULT_SYNC_PLANS_HISTORY_FILE_PREFIX =
  "sync_plans_hist_exported_on_";
export const DEFAULT_LOG_HISTORY_FILE_PREFIX = "log_hist_exported_on_";
export const DEFAULT_PROFILER_RESULT_FILE_PREFIX =
  "profiler_results_exported_on_";

export type SyncTriggerSourceType =
  | "manual"
  | "dry"
  | "auto"
  | "auto_once_init"
  | "auto_sync_on_save";
