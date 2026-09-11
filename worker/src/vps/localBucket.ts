import type { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { Readable } from "node:stream";

export interface R2HttpMetadata {
  contentType?: string;
  contentLanguage?: string;
  contentDisposition?: string;
  contentEncoding?: string;
  cacheControl?: string;
  cacheExpiry?: Date;
}

export interface R2Object {
  key: string;
  version?: string;
  size: number;
  etag: string;
  httpEtag: string;
  uploaded: Date;
  httpMetadata?: R2HttpMetadata;
  customMetadata?: Record<string, string>;
  writeHttpMetadata: (headers: Headers) => void;
}

export interface R2ObjectBody extends R2Object {
  body: ReadableStream<Uint8Array>;
  bodyUsed: boolean;
  arrayBuffer: () => Promise<ArrayBuffer>;
  text: () => Promise<string>;
  json: <T = any>() => Promise<T>;
  blob: () => Promise<Blob>;
}

export interface R2Objects {
  objects: R2Object[];
  truncated: boolean;
  cursor?: string;
  delimitedPrefixes?: string[];
}

export interface R2ListOptions {
  prefix?: string;
  cursor?: string;
  delimiter?: string;
  limit?: number;
}

export interface R2PutOptions {
  httpMetadata?: R2HttpMetadata;
  customMetadata?: Record<string, string>;
}

interface R2Row {
  key: string;
  size: number;
  uploaded: number;
  etag: string;
  custom_metadata: string | null;
  http_metadata: string | null;
}

function getPrefixRange(prefix: string): { start: string; end?: string } {
  if (!prefix) return { start: "" };
  let i = prefix.length - 1;
  while (i >= 0 && prefix.charCodeAt(i) === 0xffff) i--;
  if (i < 0) return { start: prefix };
  const nextChar = String.fromCharCode(prefix.charCodeAt(i) + 1);
  return { start: prefix, end: prefix.slice(0, i) + nextChar };
}

export class LocalDiskBucket {
  private db: DatabaseSync;
  private storageDir: string;
  private stmtGet: any;
  private stmtPut: any;
  private stmtDelete: any;

  constructor(db: DatabaseSync, storageDir: string) {
    this.db = db;
    this.storageDir = path.resolve(storageDir);
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }

    this.stmtGet = this.db.prepare(
      "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects WHERE key = ?"
    );
    this.stmtPut = this.db.prepare(
      `INSERT INTO r2_objects (key, size, uploaded, etag, custom_metadata, http_metadata)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         size = excluded.size,
         uploaded = excluded.uploaded,
         etag = excluded.etag,
         custom_metadata = excluded.custom_metadata,
         http_metadata = excluded.http_metadata`
    );
    this.stmtDelete = this.db.prepare(
      "DELETE FROM r2_objects WHERE key = ?"
    );
  }

  private getFilePath(key: string): string {
    // Sanitize path against directory traversal
    const safeKey = path.normalize(key).replace(/^(\.\.(\/|\\|$))+/, "");
    const filePath = path.join(this.storageDir, safeKey);
    if (!filePath.startsWith(this.storageDir)) {
      throw new Error(`Invalid storage path traversal attempt: ${key}`);
    }
    return filePath;
  }

  private createR2Object(row: R2Row): R2Object {
    const customMetadata = row.custom_metadata
      ? JSON.parse(row.custom_metadata)
      : undefined;
    const httpMetadata = row.http_metadata
      ? (JSON.parse(row.http_metadata) as R2HttpMetadata)
      : undefined;

    return {
      key: row.key,
      size: row.size,
      etag: row.etag,
      httpEtag: row.etag,
      uploaded: new Date(row.uploaded),
      customMetadata,
      httpMetadata,
      writeHttpMetadata(headers: Headers) {
        if (httpMetadata?.contentType) {
          headers.set("content-type", httpMetadata.contentType);
        }
        if (httpMetadata?.contentLanguage) {
          headers.set("content-language", httpMetadata.contentLanguage);
        }
        if (httpMetadata?.contentDisposition) {
          headers.set("content-disposition", httpMetadata.contentDisposition);
        }
        if (httpMetadata?.contentEncoding) {
          headers.set("content-encoding", httpMetadata.contentEncoding);
        }
        if (httpMetadata?.cacheControl) {
          headers.set("cache-control", httpMetadata.cacheControl);
        }
      },
    };
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    try {
      const row = this.stmtGet.get(key) as R2Row | undefined;
      if (!row) return null;

      const filePath = this.getFilePath(key);
      if (!fs.existsSync(filePath)) {
        // File recorded in DB but missing on disk, clean up DB
        this.stmtDelete.run(key);
        return null;
      }

      const meta = this.createR2Object(row);
      let isBodyUsed = false;

      const bodyStream = Readable.toWeb(
        fs.createReadStream(filePath)
      ) as ReadableStream<Uint8Array>;

      return {
        ...meta,
        get body() {
          isBodyUsed = true;
          return bodyStream;
        },
        get bodyUsed() {
          return isBodyUsed;
        },
        async arrayBuffer(): Promise<ArrayBuffer> {
          const buf = await fs.promises.readFile(filePath);
          return buf.buffer.slice(
            buf.byteOffset,
            buf.byteOffset + buf.byteLength
          );
        },
        async text(): Promise<string> {
          return fs.promises.readFile(filePath, "utf-8");
        },
        async json<T = any>(): Promise<T> {
          const text = await fs.promises.readFile(filePath, "utf-8");
          return JSON.parse(text);
        },
        async blob(): Promise<Blob> {
          const buf = await fs.promises.readFile(filePath);
          return new Blob([buf], {
            type: meta.httpMetadata?.contentType || "application/octet-stream",
          });
        },
      };
    } catch (err) {
      console.error(`LocalBucket get error for key "${key}":`, err);
      return null;
    }
  }

  async head(key: string): Promise<R2Object | null> {
    try {
      const row = this.stmtGet.get(key) as R2Row | undefined;
      if (!row) return null;

      const filePath = this.getFilePath(key);
      if (!fs.existsSync(filePath)) {
        this.stmtDelete.run(key);
        return null;
      }

      return this.createR2Object(row);
    } catch (err) {
      console.error(`LocalBucket head error for key "${key}":`, err);
      return null;
    }
  }

  async put(
    key: string,
    value: any,
    options?: R2PutOptions
  ): Promise<R2Object> {
    const filePath = this.getFilePath(key);
    await fs.promises.mkdir(path.dirname(filePath), { recursive: true });

    let buffer: Buffer;
    if (Buffer.isBuffer(value)) {
      buffer = value;
    } else if (value instanceof ArrayBuffer) {
      buffer = Buffer.from(value);
    } else if (ArrayBuffer.isView(value)) {
      buffer = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    } else if (typeof value === "string") {
      buffer = Buffer.from(value, "utf8");
    } else if (value instanceof Blob) {
      const ab = await value.arrayBuffer();
      buffer = Buffer.from(ab);
    } else if (value && typeof (value as any).getReader === "function") {
      // Consume ReadableStream
      const reader = (value as ReadableStream<Uint8Array>).getReader();
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        if (chunk) chunks.push(chunk);
      }
      buffer = Buffer.concat(chunks);
    } else {
      buffer = Buffer.from(String(value || ""));
    }

    await fs.promises.writeFile(filePath, buffer);

    const hash = crypto.createHash("md5").update(buffer).digest("hex");
    const etag = `"${hash}"`;
    const size = buffer.length;
    const uploaded = Date.now();
    const customMetadataStr = options?.customMetadata
      ? JSON.stringify(options.customMetadata)
      : null;
    const httpMetadataStr = options?.httpMetadata
      ? JSON.stringify(options.httpMetadata)
      : null;

    this.stmtPut.run(
      key,
      size,
      uploaded,
      etag,
      customMetadataStr,
      httpMetadataStr
    );

    const row: R2Row = {
      key,
      size,
      uploaded,
      etag,
      custom_metadata: customMetadataStr,
      http_metadata: httpMetadataStr,
    };

    return this.createR2Object(row);
  }

  async delete(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const key of list) {
      try {
        this.stmtDelete.run(key);
        const filePath = this.getFilePath(key);
        if (fs.existsSync(filePath)) {
          await fs.promises.unlink(filePath);
        }
      } catch (err) {
        console.error(`LocalBucket delete error for key "${key}":`, err);
      }
    }
  }

  async list(options?: R2ListOptions): Promise<R2Objects> {
    const prefix = options?.prefix || "";
    const cursor = options?.cursor;
    const limit = Math.min(Math.max(options?.limit || 1000, 1), 1000);
    const delimiter = options?.delimiter;

    let rows: R2Row[] = [];

    if (!prefix) {
      if (cursor) {
        rows = this.db
          .prepare(
            "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects WHERE key > ? ORDER BY key ASC LIMIT ?"
          )
          .all(cursor, limit + 1) as R2Row[];
      } else {
        rows = this.db
          .prepare(
            "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects ORDER BY key ASC LIMIT ?"
          )
          .all(limit + 1) as R2Row[];
      }
    } else {
      const range = getPrefixRange(prefix);
      if (range.end) {
        if (cursor) {
          rows = this.db
            .prepare(
              "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects WHERE key >= ? AND key < ? AND key > ? ORDER BY key ASC LIMIT ?"
            )
            .all(range.start, range.end, cursor, limit + 1) as R2Row[];
        } else {
          rows = this.db
            .prepare(
              "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects WHERE key >= ? AND key < ? ORDER BY key ASC LIMIT ?"
            )
            .all(range.start, range.end, limit + 1) as R2Row[];
        }
      } else {
        if (cursor) {
          rows = this.db
            .prepare(
              "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects WHERE key >= ? AND key > ? ORDER BY key ASC LIMIT ?"
            )
            .all(range.start, cursor, limit + 1) as R2Row[];
        } else {
          rows = this.db
            .prepare(
              "SELECT key, size, uploaded, etag, custom_metadata, http_metadata FROM r2_objects WHERE key >= ? ORDER BY key ASC LIMIT ?"
            )
            .all(range.start, limit + 1) as R2Row[];
        }
      }
    }

    // Double-check prefix safety in JS
    if (prefix) {
      rows = rows.filter((r) => r.key.startsWith(prefix));
    }

    let truncated = false;
    let nextCursor: string | undefined = undefined;

    if (rows.length > limit) {
      truncated = true;
      rows = rows.slice(0, limit);
      nextCursor = rows[rows.length - 1].key;
    }

    if (!delimiter) {
      return {
        objects: rows.map((r) => this.createR2Object(r)),
        truncated,
        cursor: nextCursor,
      };
    }

    // Process delimiter (e.g. "/" for directory-like grouping)
    const delimitedPrefixesSet = new Set<string>();
    const matchedObjects: R2Object[] = [];

    for (const r of rows) {
      const remainder = r.key.slice(prefix.length);
      const delimIndex = remainder.indexOf(delimiter);
      if (delimIndex !== -1) {
        const commonPrefix = r.key.slice(
          0,
          prefix.length + delimIndex + delimiter.length
        );
        delimitedPrefixesSet.add(commonPrefix);
      } else {
        matchedObjects.push(this.createR2Object(r));
      }
    }

    return {
      objects: matchedObjects,
      truncated,
      cursor: nextCursor,
      delimitedPrefixes: Array.from(delimitedPrefixesSet),
    };
  }
}
