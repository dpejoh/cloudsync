import localforage from "localforage";
import { extendPrototype as ep1 } from "localforage-getitems";
import { extendPrototype as ep2 } from "localforage-removeitems";
ep1(localforage);
ep2(localforage);
export type LocalForage = typeof localforage;
import { nanoid } from "nanoid";

import type { SyncPlanType } from "./sync";
import type { Entity, SUPPORTED_SERVICES_TYPE } from "./baseTypes";
import { unixTimeToStr } from "./misc";

const DB_VERSION_NUMBER_IN_HISTORY = [20211114, 20220108, 20220326, 20240220];
export const DEFAULT_DB_VERSION_NUMBER: number = 20240220;
export const DEFAULT_DB_NAME = "cloudsyncdb";
export const DEFAULT_TBL_VERSION = "schemaversion";
export const DEFAULT_SYNC_PLANS_HISTORY = "syncplanshistory";
export const DEFAULT_TBL_VAULT_RANDOM_ID_MAPPING = "vaultrandomidmapping";
export const DEFAULT_TBL_LOGGER_OUTPUT = "loggeroutput";
export const DEFAULT_TBL_SIMPLE_KV_FOR_MISC = "simplekvformisc";
export const DEFAULT_TBL_PREV_SYNC_RECORDS = "prevsyncrecords";
export const DEFAULT_TBL_PROFILER_RESULTS = "profilerresults";
interface SyncPlanRecord {
  ts: number;
  remoteType: string;
  syncPlan: string;
  vaultRandomID: string;
}

export interface InternalDBs {
  versionTbl: LocalForage;
  syncPlansTbl: LocalForage;
  vaultRandomIDMappingTbl: LocalForage;
  loggerOutputTbl: LocalForage;
  simpleKVForMiscTbl: LocalForage;
  prevSyncRecordsTbl: LocalForage;
  profilerResultsTbl: LocalForage;
}

export const prepareDBs = async (
  vaultBasePath: string,
  vaultRandomIDFromOldConfigFile: string,
  profileID: string
) => {
  const db = {
    versionTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_TBL_VERSION,
    }),
    syncPlansTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_SYNC_PLANS_HISTORY,
    }),
    vaultRandomIDMappingTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_TBL_VAULT_RANDOM_ID_MAPPING,
    }),
    loggerOutputTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_TBL_LOGGER_OUTPUT,
    }),
    simpleKVForMiscTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_TBL_SIMPLE_KV_FOR_MISC,
    }),
    prevSyncRecordsTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_TBL_PREV_SYNC_RECORDS,
    }),
    profilerResultsTbl: localforage.createInstance({
      name: DEFAULT_DB_NAME,
      storeName: DEFAULT_TBL_PROFILER_RESULTS,
    }),

  } as InternalDBs;

  // try to get vaultRandomID firstly
  let vaultRandomID = "";
  const vaultRandomIDInDB: string | null =
    await db.vaultRandomIDMappingTbl.getItem(`path2id\t${vaultBasePath}`);
  if (vaultRandomIDInDB === null) {
    if (vaultRandomIDFromOldConfigFile !== "") {
      // reuse the old config id
      vaultRandomID = vaultRandomIDFromOldConfigFile;
    } else {
      // no old config id, we create a random one
      vaultRandomID = nanoid();
    }
    // save the id back
    await db.vaultRandomIDMappingTbl.setItem(
      `path2id\t${vaultBasePath}`,
      vaultRandomID
    );
    await db.vaultRandomIDMappingTbl.setItem(
      `id2path\t${vaultRandomID}`,
      vaultBasePath
    );
  } else {
    vaultRandomID = vaultRandomIDInDB;
  }

  if (vaultRandomID === "") {
    throw Error("no vaultRandomID found or generated");
  }

  const originalVersion: number | null =
    (await db.versionTbl.getItem(`${vaultRandomID}\tversion`)) ??
    (await db.versionTbl.getItem("version"));
  if (originalVersion === null || originalVersion !== DEFAULT_DB_VERSION_NUMBER) {
    await db.versionTbl.setItem(
      `${vaultRandomID}\tversion`,
      DEFAULT_DB_VERSION_NUMBER
    );
  }

  console.info("db connected");
  return {
    db: db,
    vaultRandomID: vaultRandomID,
  };
};

export const destroyDBs = async () => {
  const req = indexedDB.deleteDatabase(DEFAULT_DB_NAME);
  req.onsuccess = (event) => {
    console.info("db deleted");
  };
  req.onblocked = (event) => {
    console.warn("trying to delete db but it was blocked");
  };
  req.onerror = (event) => {
    console.error("tried to delete db but something goes wrong!");
    console.error(event);
  };
};

export const insertSyncPlanRecordByVault = async (
  db: InternalDBs,
  syncPlan: SyncPlanType,
  vaultRandomID: string,
  remoteType: SUPPORTED_SERVICES_TYPE
) => {
  const now = Date.now();
  const record: SyncPlanRecord = {
    ts: now,
    vaultRandomID,
    remoteType,
    syncPlan: JSON.stringify(syncPlan),
  };
  await db.syncPlansTbl.setItem(`${vaultRandomID}\t${now}`, record);

  try {
    const keys = (await db.syncPlansTbl.keys())
      .filter((k) => k.startsWith(`${vaultRandomID}\t`))
      .map((k) => ({
        key: k,
        ts: Number.parseInt(k.split("\t")[1], 10),
      }))
      .filter((x) => !Number.isNaN(x.ts))
      .sort((a, b) => b.ts - a.ts);

    if (keys.length > 20) {
      const toRemove = keys.slice(20).map((x) => x.key);
      await db.syncPlansTbl.removeItems(toRemove);
    }
  } catch (err) {
    console.warn("CloudSync: Failed to prune sync plans history", err);
  }
};

export const clearAllSyncPlanRecords = async (db: InternalDBs) => {
  await db.syncPlansTbl.clear();
};

export const readAllSyncPlanRecordTextsByVault = async (
  db: InternalDBs,
  vaultRandomID: string
) => {
  const records: SyncPlanRecord[] = [];
  await db.syncPlansTbl.iterate((value, key) => {
    if (key.startsWith(`${vaultRandomID}\t`)) {
      records.push(value as SyncPlanRecord);
    }
  });
  records.sort((a, b) => b.ts - a.ts);
  return records.map((x) => x.syncPlan);
};

export const clearExpiredSyncPlanRecords = async (db: InternalDBs) => {
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const expiredTs = Date.now() - ONE_DAY_MS;

  try {
    const allKeys = await db.syncPlansTbl.keys();
    const records = allKeys
      .map((k) => ({
        key: k,
        ts: Number.parseInt(k.split("\t")[1], 10),
      }))
      .filter((x) => !Number.isNaN(x.ts));

    const toRemove = new Set<string>();
    for (const r of records) {
      if (r.ts <= expiredTs) {
        toRemove.add(r.key);
      }
    }

    if (toRemove.size > 0) {
      await db.syncPlansTbl.removeItems(Array.from(toRemove));
    }
  } catch (err) {
    console.warn("CloudSync: Failed to clear expired sync plans", err);
  }
};

export const getAllPrevSyncRecordsByVaultAndProfile = async (
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string
) => {
  const res: Entity[] = [];
  const kv: Record<string, Entity | null> =
    await db.prevSyncRecordsTbl.getItems();
  for (const key of Object.getOwnPropertyNames(kv)) {
    if (key.startsWith(`${vaultRandomID}\t${profileID}\t`)) {
      const val = kv[key];
      if (val !== null) {
        res.push(val);
      }
    }
  }
  return res;
};

export const upsertPrevSyncRecordByVaultAndProfile = async (
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string,
  prevSync: Entity
) => {
  await db.prevSyncRecordsTbl.setItem(
    `${vaultRandomID}\t${profileID}\t${prevSync.key}`,
    prevSync
  );
};

export const getPrevSyncRecordByVaultAndProfile = async (
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string,
  key: string
): Promise<Entity | null> => {
  return (
    (await db.prevSyncRecordsTbl.getItem(
      `${vaultRandomID}\t${profileID}\t${key}`
    )) ?? null
  );
};

export const clearPrevSyncRecordByVaultAndProfile = async (
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string,
  key: string
) => {
  await db.prevSyncRecordsTbl.removeItem(
    `${vaultRandomID}\t${profileID}\t${key}`
  );
};

export const getLatestVaultRevision = async (
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string
): Promise<number> => {
  const res = (await db.simpleKVForMiscTbl.getItem(
    `vault_rev_${vaultRandomID}_${profileID}`
  )) as number | null;
  return res ?? 0;
};

export const saveLatestVaultRevision = async (
  db: InternalDBs,
  vaultRandomID: string,
  profileID: string,
  rev: number
): Promise<void> => {
  await db.simpleKVForMiscTbl.setItem(
    `vault_rev_${vaultRandomID}_${profileID}`,
    rev
  );
};

export const clearAllPrevSyncRecordByVault = async (
  db: InternalDBs,
  vaultRandomID: string
) => {
  const keys = (await db.prevSyncRecordsTbl.keys()).filter((x) =>
    x.startsWith(`${vaultRandomID}\t`)
  );
  await db.prevSyncRecordsTbl.removeItems(keys);
};

export const clearAllLoggerOutputRecords = async (db: InternalDBs) => {
  await db.loggerOutputTbl.clear();
  console.debug(`successfully clearAllLoggerOutputRecords`);
};

export const upsertLastSuccessSyncTimeByVault = async (
  db: InternalDBs,
  vaultRandomID: string,
  millis: number
) => {
  await db.simpleKVForMiscTbl.setItem(
    `${vaultRandomID}-lastSuccessSyncMillis`,
    millis
  );
};

export const getLastSuccessSyncTimeByVault = async (
  db: InternalDBs,
  vaultRandomID: string
) => {
  return (await db.simpleKVForMiscTbl.getItem(
    `${vaultRandomID}-lastSuccessSyncMillis`
  )) as number | null | undefined;
};

export const upsertLastFailedSyncTimeByVault = async (
  db: InternalDBs,
  vaultRandomID: string,
  millis: number
) => {
  await db.simpleKVForMiscTbl.setItem(
    `${vaultRandomID}-lastFailedSyncMillis`,
    millis
  );
};

export const getLastFailedSyncTimeByVault = async (
  db: InternalDBs,
  vaultRandomID: string
) => {
  return (await db.simpleKVForMiscTbl.getItem(
    `${vaultRandomID}-lastFailedSyncMillis`
  )) as number | null | undefined;
};

export const upsertPluginVersionByVault = async (
  db: InternalDBs,
  vaultRandomID: string,
  newVersion: string
) => {
  let oldVersion: string | null = await db.simpleKVForMiscTbl.getItem(
    `${vaultRandomID}-pluginversion`
  );
  if (oldVersion === null) {
    oldVersion = "0.0.0";
  }
  await db.simpleKVForMiscTbl.setItem(
    `${vaultRandomID}-pluginversion`,
    newVersion
  );

  return {
    oldVersion: oldVersion,
    newVersion: newVersion,
  };
};

export const insertProfilerResultByVault = async (
  db: InternalDBs,
  profilerStr: string,
  vaultRandomID: string,
  remoteType: SUPPORTED_SERVICES_TYPE
) => {
  const now = Date.now();
  await db.profilerResultsTbl.setItem(`${vaultRandomID}\t${now}`, profilerStr);

  // clear older one while writing
  const records = (await db.profilerResultsTbl.keys())
    .filter((x) => x.startsWith(`${vaultRandomID}\t`))
    .map((x) => Number.parseInt(x.split("\t")[1]));
  records.sort((a, b) => -(a - b)); // descending
  while (records.length > 5) {
    const ts = records.pop()!;
    await db.profilerResultsTbl.removeItem(`${vaultRandomID}\t${ts}`);
  }
};

export const readAllProfilerResultsByVault = async (
  db: InternalDBs,
  vaultRandomID: string
) => {
  const records = [] as { val: string; ts: number }[];
  await db.profilerResultsTbl.iterate((value, key, iterationNumber) => {
    if (key.startsWith(`${vaultRandomID}\t`)) {
      records.push({
        val: value as string,
        ts: Number.parseInt(key.split("\t")[1]),
      });
    }
  });
  records.sort((a, b) => -(a.ts - b.ts)); // descending

  if (records === undefined) {
    return [] as string[];
  } else {
    return records.map((x) => x.val);
  }
};

