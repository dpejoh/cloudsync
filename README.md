# CloudSync

Fast, zero-knowledge encrypted sync for Obsidian. Powered by Cloudflare Workers & R2 or self-hosted VPS.

CloudSync is an independent, lightweight sync plugin for Obsidian. It provides client-side zero-knowledge encryption, debounced fast sync, version history, cloud trash, and multi-device support without third-party vendor lock-in.

---

## Features

- **Zero-Knowledge Encryption**: AES-256 client-side encryption. Note contents, filenames, and folder structures are encrypted before leaving your device.
- **Dual Backend**:
  - **Cloudflare Workers & R2**: Serverless, zero egress fees, runs on the Cloudflare free tier.
  - **Self-Hosted VPS (Docker)**: Standalone Node.js server with embedded SQLite and local disk storage.
- **Fast Sync on Edit**: Debounced background sync (800ms) with change polling.
- **Version History**: Snapshot revisions with side-by-side line diff viewer and one-click restore.
- **Cloud Trash**: Soft-deletes notes with 30-day retention, preview, and bulk restore.
- **Device Settings Backup**: Backup and restore themes, snippets, plugins, and hotkeys.
- **Two-Factor Authentication**: Standard 6-digit TOTP (Google Authenticator, Aegis, 1Password).
- **Vault Sharing**: Share vaults with other users by username with role-based permissions.
- **Lightweight**: Zero cloud SDK bloat (< 850 KB compiled bundle).

---

## Quick Start

### 1. Deploy Backend

#### Option A: Cloudflare Workers
See [Worker Setup Guide](docs/WORKER_SETUP.md) for details.

```bash
cd worker
npm install
npx wrangler login
npx wrangler r2 bucket create cloudsync-vault
npx wrangler kv namespace create CLOUDSYNC_KV
npx wrangler deploy
```

#### Option B: Self-Host via Docker (VPS)
```bash
docker compose up -d
```
Server runs on port `3000` with data stored in `./data`.

---

## Installation

### Manual Install
1. Download `main.js`, `manifest.json`, and `styles.css` from the latest release.
2. In your vault, create `.obsidian/plugins/cloudsync/`.
3. Copy the three files into that folder.
4. In Obsidian, go to **Settings -> Community plugins**, reload, and enable **CloudSync**.

---

## Commands

- `Sync vault now`: Trigger immediate bidirectional sync
- `Dry run (Preview changes)`: Compare local vs remote files without writing to disk
- `Open version history`: View history and line diffs for active file
- `Open cloud trash`: Browse and restore deleted files
- `Open sync log`: View recent sync activity
- `Choose remote vault`: Connect or switch remote vaults
- `Backup device settings`: Back up settings, plugins, and themes

---

---

## License

Licensed under the **Apache License, Version 2.0**.
