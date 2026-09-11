import type { DatabaseSync } from "node:sqlite";

export class LocalSqliteKV {
  private db: DatabaseSync;
  private stmtGet: any;
  private stmtPut: any;
  private stmtDelete: any;
  private stmtCleanup: any;
  private lastCleanup: number = 0;

  constructor(db: DatabaseSync) {
    this.db = db;
    this.stmtGet = this.db.prepare(
      "SELECT value, expires_at FROM kv_store WHERE key = ?"
    );
    this.stmtPut = this.db.prepare(
      `INSERT INTO kv_store (key, value, expires_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         value = excluded.value,
         expires_at = excluded.expires_at`
    );
    this.stmtDelete = this.db.prepare(
      "DELETE FROM kv_store WHERE key = ?"
    );
    this.stmtCleanup = this.db.prepare(
      "DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at <= ?"
    );
  }

  private maybeCleanup() {
    const now = Date.now();
    // Run garbage collection at most once every 60 seconds
    if (now - this.lastCleanup > 60_000) {
      this.lastCleanup = now;
      try {
        this.stmtCleanup.run(now);
      } catch (err) {
        console.error("KV cleanup error:", err);
      }
    }
  }

  async get(key: string): Promise<string | null> {
    this.maybeCleanup();
    try {
      const row = this.stmtGet.get(key) as
        | { value: string; expires_at: number | null }
        | undefined;

      if (!row) {
        return null;
      }

      if (row.expires_at !== null && row.expires_at <= Date.now()) {
        this.stmtDelete.run(key);
        return null;
      }

      return row.value;
    } catch (err) {
      console.error(`KV get error for key "${key}":`, err);
      return null;
    }
  }

  async put(
    key: string,
    value: string,
    options?: { expirationTtl?: number }
  ): Promise<void> {
    try {
      const expiresAt = options?.expirationTtl
        ? Date.now() + options.expirationTtl * 1000
        : null;

      this.stmtPut.run(key, String(value), expiresAt);
    } catch (err) {
      console.error(`KV put error for key "${key}":`, err);
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    try {
      this.stmtDelete.run(key);
    } catch (err) {
      console.error(`KV delete error for key "${key}":`, err);
      throw err;
    }
  }
}
