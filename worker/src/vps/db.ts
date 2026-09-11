import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

export interface VpsDatabase {
  db: DatabaseSync;
  close: () => void;
}

export function initDatabase(dbPath: string): DatabaseSync {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new DatabaseSync(dbPath);

  // Enable WAL (Write-Ahead Logging) and normal synchronous for fast concurrent writes
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA synchronous = NORMAL;");
  db.exec("PRAGMA temp_store = MEMORY;");

  // 1. Table for Key-Value store (KVNamespace emulator)
  db.exec(`
    CREATE TABLE IF NOT EXISTS kv_store (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      expires_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_kv_expires ON kv_store(expires_at);
  `);

  // 2. Table for R2 object metadata (R2Bucket emulator)
  db.exec(`
    CREATE TABLE IF NOT EXISTS r2_objects (
      key TEXT PRIMARY KEY,
      size INTEGER NOT NULL,
      uploaded INTEGER NOT NULL,
      etag TEXT NOT NULL,
      custom_metadata TEXT,
      http_metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_r2_key ON r2_objects(key);
  `);

  return db;
}
