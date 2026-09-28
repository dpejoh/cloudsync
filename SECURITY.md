# Security Policy

## Reporting a vulnerability

Please report security issues privately to the maintainer (open a
[GitHub security advisory](https://github.com/dpejoh/cloudsync/security/advisories/new)
or contact the author directly), not as a public issue. Include the affected version,
reproduction steps, and impact when possible.

## Supported versions

Only the latest release of the plugin and the worker in this repository are supported.

## Security model

CloudSync uses end-to-end encryption with a zero-knowledge backend:

- A random **master key** (MK) is generated per account and wrapped by a password-derived
  **KEK** (Argon2id, per-account random salt) and, when configured, by a high-entropy
  **recovery key**.
- Each vault has its own random **vault key** (VK). Owned vaults wrap it under the MK;
  shared vaults deliver it through X25519 **envelopes** sealed to each collaborator's
  public key.
- File contents and names are encrypted with the VK; every object also carries an HMAC
  binding its encrypted name to its content, so swaps or modifications are detected.
- The server stores only ciphertext, encrypted/MACed key material, and public keys.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Known limitations

- **Server-visible metadata:** object counts, sizes, timestamps, device names, access
  patterns, and vault names are not encrypted.
- **TOTP is server-verified:** a server breach exposes the second factor (but not the
  vault keys).
- **Availability:** a malicious or broken server can withhold or delete data; clients
  detect corruption but cannot force the server to serve data.
- **Revocation requires a re-key:** removing a collaborator only fully invalidates their
  access after rotating the vault key (offered automatically in the UI).
- **Recovery without the recovery key:** resetting a password with only a TOTP code
  cannot unwrap the master key, so existing notes become unreadable. The UI warns first.
- **Legacy vaults:** `openssl-base64` is unauthenticated, and pre-v2 accounts use one
  password-derived key for all vaults. Fresh single-user setups use the v2 key model;
  only their login verifier is PBKDF2-based, since the server validates the configured
  master password without Argon2.

## Operational guidance

- Deploy the worker with a strong `JWT_SECRET` (Cloudflare secret or VPS env var);
  the backend refuses to run without one.
- Always terminate TLS in front of self-hosted deployments.
- Back up the VPS `./data` directory; it contains the verifier hashes, TOTP secrets,
  encrypted key material and all vault data.
