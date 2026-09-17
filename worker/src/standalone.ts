import { serve } from "@hono/node-server";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import app from "./index";
import { initDatabase } from "./vps/db";
import { LocalSqliteKV } from "./vps/localKv";
import { LocalDiskBucket } from "./vps/localBucket";

// Configuration from environment variables
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
const WORKER_MODE = (process.env.WORKER_MODE || "multi") as "single" | "multi";
const SINGLE_USER_PASSWORD = process.env.SINGLE_USER_PASSWORD;

// Persist or initialize JWT Secret
const secretFilePath = path.join(DATA_DIR, ".jwt_secret");
let JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  if (fs.existsSync(secretFilePath)) {
    JWT_SECRET = fs.readFileSync(secretFilePath, "utf8").trim();
  } else {
    JWT_SECRET = crypto.randomBytes(32).toString("hex");
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(secretFilePath, JWT_SECRET, "utf8");
    console.log("generated persistent jwt secret in data directory");
  }
}

// Initialize SQLite database and storage adapters
const dbPath = path.join(DATA_DIR, "cloudsync.db");
const storageDir = path.join(DATA_DIR, "storage");

console.log(`data dir: ${DATA_DIR}`);
console.log(`sqlite db: ${dbPath}`);
console.log(`storage dir: ${storageDir}`);

const db = initDatabase(dbPath);
const localKv = new LocalSqliteKV(db);
const localBucket = new LocalDiskBucket(db, storageDir);

const env = {
  CLOUDSYNC_BUCKET: localBucket as unknown as R2Bucket,
  CLOUDSYNC_KV: localKv as unknown as KVNamespace,
  JWT_SECRET,
  WORKER_MODE,
  SINGLE_USER_PASSWORD,
};

// Start standalone HTTP server
const server = serve(
  {
    fetch: (req) => app.fetch(req, env),
    port: PORT,
    hostname: HOST,
  },
  (info) => {
    console.log(`cloudsync server running on http://${info.address}:${info.port} (mode: ${WORKER_MODE})`);
  }
);

// Graceful shutdown
function shutdown(signal: string) {
  console.log(`\nReceived ${signal}. Shutting down gracefully...`);
  server.close(() => {
    try {
      db.close();
    } catch {}
    console.log("Server closed. Good bye!");
    process.exit(0);
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
