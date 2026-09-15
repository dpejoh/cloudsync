# Backend Deployment Guide

Instructions for deploying the CloudSync backend on Cloudflare Workers or a self-hosted Linux VPS.

---

## Option 1: Cloudflare Workers

### 1. Prerequisites
- A [Cloudflare account](https://dash.cloudflare.com/sign-up)
- Node.js (v18+)

### 2. Setup and Deploy

```bash
cd worker
npm install
npx wrangler login

# Create R2 bucket and KV namespace
npx wrangler r2 bucket create cloudsync-vault
npx wrangler kv namespace create CLOUDSYNC_KV
```

Copy the returned `id` from the KV command into `worker/wrangler.jsonc` under `kv_namespaces.id`.

Deploy:
```bash
npx wrangler deploy
```

The output URL (e.g. `https://cloudsync.<subdomain>.workers.dev`) is your sync server address in the plugin settings.

---

## Option 2: Self-Hosted VPS (Docker)

### 1. Docker Compose
Run directly from repository root:
```bash
docker compose up -d
```

The service runs on port `3000` with data stored in `./data`.

### 2. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `DATA_DIR` | `./data` | Path to persistent storage and SQLite database |
| `JWT_SECRET` | (auto-generated) | Secret key for signing tokens |

---

## Obsidian Configuration

1. In Obsidian, open **Settings -> CloudSync**.
2. Set **Server URL** to your Worker URL or VPS address (`https://...`).
3. Click **Create Account** or **Log In**.
4. Create or select a remote vault to begin syncing.
