# Backend Deployment Guide

Instructions for deploying the CloudSync backend on Cloudflare Workers or a self-hosted Linux VPS.

> **Security essentials before you deploy**
> - Never commit `JWT_SECRET`. Use `wrangler secret put JWT_SECRET` on Cloudflare or the `JWT_SECRET` environment variable on a VPS.
> - Always terminate TLS (HTTPS) in front of a VPS deployment. Tokens and password verifiers must never travel over plain HTTP.
> - Single-user mode requires `SINGLE_USER_PASSWORD` to be set on a fresh deployment; otherwise login is refused so that nobody can claim the worker.

---

## Option 1: Cloudflare Workers

### 1. Prerequisites
- A [Cloudflare account](https://dash.cloudflare.com/sign-up)
- Node.js (v22+)

### 2. Create storage
```bash
cd worker
npm install
npx wrangler login

npx wrangler r2 bucket create cloudsync-vault
npx wrangler kv namespace create CLOUDSYNC_KV
```

Copy the returned KV `id` into `worker/wrangler.jsonc` (replace `REPLACE_WITH_YOUR_KV_NAMESPACE_ID`).

### 3. Set the JWT secret
```bash
# Generate a strong secret and store it as a Worker secret (never in the config file)
openssl rand -hex 32 | npx wrangler secret put JWT_SECRET
```

The Worker refuses to serve authenticated routes if `JWT_SECRET` is missing or shorter than 16 characters.

### 4. Deploy
```bash
npx wrangler deploy
```

The output URL (e.g. `https://cloudsync.<subdomain>.workers.dev`) is your sync server address in the plugin settings.

### Limits and quotas
- Single object size: 100 MB
- Per-account storage: 10 GB (enforced; requests fail with `413` when exceeded)
- Change feed: the last 100 mutations per vault; clients trigger a full scan when they fall behind

---

## Option 2: Self-Hosted VPS (Docker)

### 1. Start the service
Run from the repository root:
```bash
docker compose up -d
```

The service listens on port `3000` and stores all data in `./data` (`cloudsync.db`, `storage/`, `.jwt_secret`). The container runs as an unprivileged user via an entrypoint that fixes data-volume ownership.

### 2. Put it behind HTTPS
CloudSync does **not** terminate TLS itself. Use Caddy, nginx, or Traefik to serve HTTPS, and keep port `3000` bound to localhost whenever possible:

```caddy
sync.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

If (and only if) your reverse proxy sets `X-Real-IP`, you may also set `TRUST_PROXY=1` so auth rate limiting uses the real client address.

### 3. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `HOST` | `0.0.0.0` | HTTP listen host |
| `DATA_DIR` | `./data` | Persistent storage and SQLite database |
| `JWT_SECRET` | auto-generated in `DATA_DIR/.jwt_secret` | Secret for signing tokens |
| `WORKER_MODE` | `multi` | `multi` (accounts + 2FA) or `single` (one master password) |
| `SINGLE_USER_PASSWORD` | _(unset)_ | **Required** for fresh `single` deployments; login is refused without it |
| `TRUST_PROXY` | _(unset)_ | `1` to trust `X-Real-IP` for rate limiting (only behind a trusted proxy) |

### 4. Backups
Back up the whole `./data` directory (SQLite WAL files included). Without it, password verifiers, TOTP secrets, version history, and trash are lost.

---

## Obsidian Configuration

1. In Obsidian, open **Settings -> CloudSync**.
2. Set **Server URL** to your Worker URL or VPS address (`https://...`).
3. Click **Create Account** or **Log In**.
4. Save the **recovery key** shown after registration; it is required to reset your password without your authenticator app.
5. Create or select a remote vault to begin syncing.

---

## Security model notes

- Note contents and file names are encrypted on the client. The server necessarily sees object counts, approximate sizes, timestamps, and access patterns.
- Passwords are verified with a PBKDF2-derived verifier; the derived note-encryption key never leaves the client. A server compromise does not directly reveal note contents, but users should still choose a strong, unique password.
- Password changes and recovery invalidate previously issued tokens. Other devices must log in again.
- The legacy `openssl-base64` encryption mode does not authenticate note contents and should be migrated to the default `rclone-base64` mode.
- Cloud trash is retained for 30 days; history keeps the latest 50 versions per file (2 MB per version).
