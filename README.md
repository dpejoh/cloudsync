# CloudSync

Fast, zero-knowledge encrypted sync for Obsidian. Powered by Cloudflare Workers & R2 or self-hosted VPS.

CloudSync is an independent sync plugin for Obsidian, originally forked from [remotely-save](https://github.com/fyears/remotely-save). It provides client-side zero-knowledge encryption, debounced fast sync, version history, cloud trash, and multi-device support without third-party vendor lock-in.

---

## Why CloudSync?

- **Support Obsidian**: CloudSync is not meant to replace supporting the devs. If you can afford Obsidian Sync, please support Kepano and the core team.
- **Most free options are impractical**: Setups like original Remotely Save over Google Drive, OneDrive, or WebDAV are fragile, slow, and frustrating to maintain. Generic cloud drives were not built for note sync.
- **Why only Workers and VPS?**: They are the only practical platforms for real-time note sync. Cloudflare Workers + R2 provides the best free serverless tier, while Docker on a private VPS covers self-hosters. No other backends are needed.
- **Zero-friction privacy**: An out-of-the-box, zero-knowledge encrypted sync engine on free infrastructure without setup headaches.

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

## Authentication & Recovery

CloudSync uses **Username + Password + TOTP (2FA)** instead of email:

- **Zero email dependencies**: No transactional mail services (Resend, SendGrid) or VPS mail daemons required. Deployments stay completely self-contained.
- **Save your recovery key**: Registration generates a recovery key used to reset your password if you lose your authenticator app. It is shown once and stored locally; keep it offline. Password reset works with either the recovery key or a TOTP code.
- **Encryption caveat**: resetting your password derives a new encryption key. Notes encrypted with the old password remain unreadable unless you still know the old password. With zero-knowledge encryption there is no server-side recovery of note contents.

---

## Security Notes

- **Server secret**: deployments require `JWT_SECRET` (Cloudflare secret or VPS env var). The backend refuses authenticated traffic when it is missing, so a misconfigured instance fails closed instead of accepting forged tokens.
- **Encrypted-mode limits**: the server never sees note contents or file names, but it necessarily sees object counts, approximate sizes, timestamps, and access patterns.
- **Server-initiated tampering**: with the default `rclone-base64` mode, content is authenticated (tampering is detected), but a malicious server can still replay or delete whole objects. The legacy `openssl-base64` mode is unauthenticated and should not be used for new vaults.
- **Limits**: 100 MB per object, 10 GB per account, cloud trash retained 30 days, up to 50 history versions per file (2 MB each).
- **VPS**: always run behind HTTPS; `docker compose` starts the server as an unprivileged user with `no-new-privileges`.

---

## Credits

CloudSync was originally forked from [remotely-save](https://github.com/fyears/remotely-save) by [fyears](https://github.com/fyears). While the architecture has evolved with dedicated Cloudflare Worker / VPS backends, client-side zero-knowledge encryption, and a modernized sync engine, credit goes to fyears and the original contributors for laying the groundwork.

---

## License

Licensed under the **Apache License, Version 2.0**.
