# CloudSync Architecture

This document describes the protocol v2 key architecture. The server is untrusted
for **confidentiality and integrity**: it stores only ciphertext, encrypted key
blobs and public keys. Only protocol v2 accounts are supported; older accounts must
be recreated.

## Threat model

- The server **must not** be able to read note contents, file names, or any secret key.
- The server **must not** be able to silently swap, reorder, or modify objects without
  the client detecting it.
- The server **can** deny service or withhold data; clients detect corruption on read
  but cannot force delivery.
- Sharing grants access to **one vault**, must be revocable, and revocation must
  invalidate the shared key.

## Key hierarchy

```
account password ──Argon2id(per-account salt)──► KEK + auth verifier
recovery key     ──HKDF-SHA256────────────────► recovery KEK
                                                  │
random Master Key (MK) ── wrapped by KEK ◄────────┘  (both wrap the same MK)
                       └─ wrapped by recovery KEK
                       └─ identity X25519 private key (wrapped by MK)

per-vault random key (VK)
  owner:        wrapped by MK
  collaborator: sealed to their X25519 public key ("envelope")
  content:      VK is the rclone password for that vault's objects
  files:        HMAC(VK, encrypted-name || sha256(content)) stored on the object
```

- **MK and VK are random 256-bit keys.** The password only unlocks the MK, so a
  password change re-wraps keys instead of re-encrypting data. A 120-bit **recovery
  key** (shown once) wraps the same MK, so a password reset keeps notes readable.
- **Argon2id** (m=19 MiB, t=2, p=1) with a random per-account salt, pinned by the
  client protocol so the server cannot downgrade it.
- **X25519 envelopes** are bound to `(vault, key version, owner, recipient)` and
  authenticated, so a key cannot be replayed into another vault or user.

## Account lifecycle

| Step | What happens |
|---|---|
| Register | Client generates the KDF salt, derives KEK + verifier, generates MK/identity, wraps the MK (KEK + recovery key) and stores the key material. |
| Login | Client fetches the KDF descriptor (`/api/auth/params/:username`), derives the verifier, logs in, fetches the key material, verifies its MAC and unwraps the MK. |
| Password change | Unwrap MK with the old KEK, re-wrap with the new one, upload. Data untouched. |
| Recovery (recovery key) | Unwrap MK with the recovery KEK, re-wrap under the new password. Data untouched. |
| Recovery (TOTP only) | Allowed, but the MK stays locked: existing notes become unreadable. The UI warns first. |

Key material is authenticated with `HMAC(KEK, canonical-payload)` and carries a
monotonic revision, so the server cannot forge or roll back key material.

## Vaults and sharing

- **Create/connect (owner):** a random VK is generated on first use and wrapped by the MK.
- **Invite:** the owner fetches the invitee's public key, seals the VK to it, and stores
  the envelope. The invitee's client fetches and opens it automatically.
- **Remove collaborator:** access and envelope are deleted server-side. The owner is then
  offered a **re-key**, the only way to invalidate the key the collaborator already
  received. A re-key can also be started from the Collaborators dialog or
  Settings -> Advanced.
- **Re-key:** the server locks the vault (reads and writes from other devices get `409`).
  The rotation client then:

  1. derives the new key deterministically from `MK + vault + version`, so an interrupted
     rotation is idempotent and can be retried;
  2. classifies every remote object by the key that decrypts it;
  3. re-encrypts the remaining old objects in a bounded parallel pool and verifies the
     new generation;
  4. removes the old objects through the server's bulk purge endpoint and drops old
     history/trash;
  5. redistributes envelopes to the remaining members and commits the new `keyVersion`.

  A rotation resumes from the classified state at any point, including "everything
  rewritten but not committed"; objects that decrypt with neither key abort it. Old keys
  are dead afterwards. Since rclone uses one key for contents and names, a re-key must
  rewrite all data; latency is parallelized, bandwidth is not.

## Encryption of files

- Content and names use `rclone-crypt` (XSalsa20-Poly1305 for content, AES-EME for
  names) with the **vault key** as the password. The legacy `openssl-base64` mode is
  unauthenticated and should not be used for new vaults.
- Every object also carries `x-integrity`, an HMAC over
  `encrypted name || sha256(ciphertext)` (key derived from the VK), verified on read so
  a malicious server cannot swap ciphertext between files.

## Server surface (v2 additions)

| Endpoint | Purpose |
|---|---|
| `GET /api/auth/params/:username` | Non-secret KDF salt/params. |
| `GET/PUT /api/user/keymaterial` | Opaque, MACed key material; revision-monotonic. |
| `GET /api/user/pubkey/:username` | Public identity key for envelope sealing. |
| `GET/PUT/DELETE /api/vaults/:name/envelope[/:recipient]` | Per-member encrypted vault keys. |
| `POST /api/vaults/:name/rotation` | `begin` / `commit` / `abort` a re-key. |
| `POST /api/vaults/:name/purge` | Purges history/trash during a re-key. |

## Single-user mode

Single-user mode uses the same v2 key model; only the **login verifier** stays
PBKDF2-based, because the server checks `SINGLE_USER_PASSWORD` without Argon2, which does
not fit the free Cloudflare Workers CPU budget. The master password still protects the
key material client-side with Argon2id.
