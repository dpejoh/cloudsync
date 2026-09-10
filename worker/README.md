# CloudSync Backend Engine

Dual-runtime backend for the CloudSync Obsidian plugin. Built with [Hono](https://hono.dev/).

Supports two deployment targets with complete feature parity:
1. **Cloudflare Workers**: Serverless edge deployment with Cloudflare R2 object storage and KV metadata. Free under Cloudflare free tier.
2. **Private VPS / Self-Hosted**: Standalone Node.js server with embedded SQLite and local filesystem storage.

---

## Quick Start

### Cloudflare Workers
```bash
npm install
npx wrangler login
npx wrangler r2 bucket create cloudsync-vault
npx wrangler kv namespace create CLOUDSYNC_KV
npx wrangler deploy
```

### Self-Hosted VPS (Docker)
From repository root:
```bash
docker compose up -d
```
Server listens on port `3000` with data stored in `./data`.

### Self-Hosted VPS (Node.js)
```bash
npm install
npm run build:vps
PORT=3000 DATA_DIR=./data npm run start:vps
```

---

## Test Suite

Run the automated parity test suite:
```bash
npm run test:vps
```

---

## Storage Layout

- Notes: `users/{userId}/vaults/{vaultName}/*`
- Version History: `users/{userId}/history/{vaultName}/*`
- Cloud Trash: `users/{userId}/trash/{vaultName}/*`
- Device Backups: `device_configs/{deviceId}/*`
- User Data: `system/users/{username}.json`
