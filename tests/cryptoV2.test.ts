import {
  ACCOUNT_KDF_PARAMS,
  CRYPTO_V2_PROTOCOL,
  type AccountKeyMaterial,
  assertSupportedKdf,
  b64uDecode,
  b64uEncode,
  canonicalJson,
  computeIntegrityMac,
  constantTimeEqual,
  createAccountKeyMaterial,
  deriveAccountKeys,
  deriveIntegrityKey,
  envelopeContext,
  generateRecoveryKey,
  generateSymmetricKey,
  getVaultKey,
  identityFingerprint,
  macKeyMaterial,
  newKdfDescriptor,
  openVaultKeyEnvelope,
  rewrapKeyMaterial,
  rewrapKeyMaterialFromRecovery,
  sealVaultKeyForRecipient,
  unlockKeyMaterial,
  unlockKeyMaterialWithRecovery,
  utf8,
  verifyIntegrityMac,
  verifyKeyMaterialMac,
  vaultKeyToPassword,
  withVaultKey,
  withoutVaultKey,
  wrapMasterKey,
  wrapVaultKey,
  openBytes,
  sealBytes,
  unwrapMasterKey,
  unwrapVaultKey,
  generateIdentityKeyPair,
  sealIdentityPrivateKey,
  openIdentityPrivateKey,
} from "../src/cryptoV2";

const PASSWORD = "correct horse battery staple";
const USERNAME = "alice";

describe("cryptoV2 encoding", () => {
  it("canonical JSON sorts keys recursively", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    expect(canonicalJson({ a: [3, 1, { z: 1, y: 2 }] })).toBe('{"a":[3,1,{"y":2,"z":1}]}');
  });

  it("base64url round trips", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(b64uDecode(b64uEncode(bytes))).toEqual(bytes);
  });

  it("constant-time compare", () => {
    expect(constantTimeEqual(utf8("abc"), utf8("abc"))).toBe(true);
    expect(constantTimeEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(constantTimeEqual(utf8("abc"), utf8("ab"))).toBe(false);
  });
});

describe("cryptoV2 account KDF", () => {
  it("derives deterministic keys and a stable verifier", async () => {
    const kdf = newKdfDescriptor();
    const a = await deriveAccountKeys(PASSWORD, kdf, USERNAME);
    const b = await deriveAccountKeys(PASSWORD, kdf, USERNAME);
    expect(constantTimeEqual(a.kek, b.kek)).toBe(true);
    expect(a.authVerifier).toBe(b.authVerifier);
  });

  it("verifier differs for a different salt", async () => {
    const a = await deriveAccountKeys(PASSWORD, newKdfDescriptor(), USERNAME);
    const b = await deriveAccountKeys(PASSWORD, newKdfDescriptor(), USERNAME);
    expect(a.authVerifier).not.toBe(b.authVerifier);
    expect(constantTimeEqual(a.kek, b.kek)).toBe(false);
  });

  it("binds the verifier to the username", async () => {
    const kdf = newKdfDescriptor();
    const a = await deriveAccountKeys(PASSWORD, kdf, "alice");
    const b = await deriveAccountKeys(PASSWORD, kdf, "Alice");
    const c = await deriveAccountKeys(PASSWORD, kdf, "bob");
    expect(a.authVerifier).toBe(b.authVerifier);
    expect(a.authVerifier).not.toBe(c.authVerifier);
  });

  it("rejects downgraded or malformed KDF parameters", () => {
    const kdf = newKdfDescriptor();
    expect(() => assertSupportedKdf(kdf)).not.toThrow();
    expect(() => assertSupportedKdf({ ...kdf, m: 8 })).toThrow();
    expect(() => assertSupportedKdf({ ...kdf, alg: "pbkdf2" as any })).toThrow();
    expect(() => assertSupportedKdf({ ...kdf, salt: "" })).toThrow();
  });
});

describe("cryptoV2 symmetric wraps", () => {
  it("round trips sealed bytes", async () => {
    const key = generateSymmetricKey();
    const sealed = await sealBytes(key, utf8("hello"), "aad");
    expect(new TextDecoder().decode(await openBytes(key, sealed, "aad"))).toBe("hello");
  });

  it("fails with a wrong key, wrong AAD, or tampered ciphertext", async () => {
    const key = generateSymmetricKey();
    const other = generateSymmetricKey();
    const sealed = await sealBytes(key, utf8("hello"), "aad");
    await expect(openBytes(other, sealed, "aad")).rejects.toThrow();
    await expect(openBytes(key, sealed, "other")).rejects.toThrow();
    const raw = b64uDecode(sealed);
    raw[raw.length - 1] ^= 0x01;
    await expect(openBytes(key, b64uEncode(raw), "aad")).rejects.toThrow();
  });

  it("wraps and unwraps the master key", async () => {
    const kek = generateSymmetricKey();
    const mk = generateSymmetricKey();
    const wrapped = await wrapMasterKey(kek, mk);
    expect(constantTimeEqual(await unwrapMasterKey(kek, wrapped), mk)).toBe(true);
    await expect(unwrapMasterKey(generateSymmetricKey(), wrapped)).rejects.toThrow();
  });
});

describe("cryptoV2 vault keys", () => {
  it("wraps per vault and version, rejecting context swaps", async () => {
    const mk = generateSymmetricKey();
    const vk = generateSymmetricKey();
    const wrapped = await wrapVaultKey(mk, "vaultA", 1, vk);
    expect(constantTimeEqual(await unwrapVaultKey(mk, "vaultA", 1, wrapped), vk)).toBe(true);
    await expect(unwrapVaultKey(mk, "vaultB", 1, wrapped)).rejects.toThrow();
    await expect(unwrapVaultKey(mk, "vaultA", 2, wrapped)).rejects.toThrow();
  });

  it("represents vault keys as hex passwords", () => {
    const vk = new Uint8Array([0, 15, 255]);
    expect(vaultKeyToPassword(vk)).toBe("000fff");
  });
});

describe("cryptoV2 identity", () => {
  it("generates a keypair and wraps the private key", async () => {
    const mk = generateSymmetricKey();
    const identity = generateIdentityKeyPair();
    expect(b64uDecode(identity.publicKey).length).toBe(32);
    const sealed = await sealIdentityPrivateKey(mk, identity.privateKey);
    expect(constantTimeEqual(await openIdentityPrivateKey(mk, sealed), identity.privateKey)).toBe(true);
  });

  it("produces a stable fingerprint", async () => {
    const identity = generateIdentityKeyPair();
    const fp1 = await identityFingerprint(identity.publicKey);
    const fp2 = await identityFingerprint(identity.publicKey);
    expect(fp1).toBe(fp2);
    expect(fp1).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/);
  });
});

describe("cryptoV2 envelopes", () => {
  it("seals a vault key to a recipient", async () => {
    const identity = generateIdentityKeyPair();
    const vk = generateSymmetricKey();
    const ctx = { v: CRYPTO_V2_PROTOCOL, vaultId: "vaultA", keyVersion: 1, ownerId: "owner", recipientId: "bob" };
    const envelope = await sealVaultKeyForRecipient(vk, identity.publicKey, ctx);
    expect(constantTimeEqual(await openVaultKeyEnvelope(envelope, identity.privateKey), vk)).toBe(true);
  });

  it("rejects the wrong recipient and tampered context", async () => {
    const recipient = generateIdentityKeyPair();
    const other = generateIdentityKeyPair();
    const vk = generateSymmetricKey();
    const ctx = { v: CRYPTO_V2_PROTOCOL, vaultId: "vaultA", keyVersion: 1, ownerId: "owner", recipientId: "bob" };
    const envelope = await sealVaultKeyForRecipient(vk, recipient.publicKey, ctx);
    await expect(openVaultKeyEnvelope(envelope, other.privateKey)).rejects.toThrow();
    await expect(
      openVaultKeyEnvelope({ ...envelope, vaultId: "vaultB" }, recipient.privateKey)
    ).rejects.toThrow();
    await expect(
      openVaultKeyEnvelope({ ...envelope, keyVersion: 2 }, recipient.privateKey)
    ).rejects.toThrow();
    expect(envelopeContext(ctx)).toContain("vault=vaultA");
  });
});

describe("cryptoV2 key material", () => {
  async function freshMaterial() {
    const created = await createAccountKeyMaterial({
      accountId: "user-1",
      username: USERNAME,
      password: PASSWORD,
      recoveryKey: generateRecoveryKey(),
    });
    return created;
  }

  it("creates a verifiable, unlockable document", async () => {
    const { keyMaterial, kek, masterKey } = await freshMaterial();
    expect(keyMaterial.v).toBe(CRYPTO_V2_PROTOCOL);
    expect(keyMaterial.kdf.m).toBe(ACCOUNT_KDF_PARAMS.m);
    expect(await verifyKeyMaterialMac(keyMaterial, kek)).toBe(true);
    const unlocked = await unlockKeyMaterial(keyMaterial, kek);
    expect(constantTimeEqual(unlocked.masterKey, masterKey)).toBe(true);
  });

  it("detects tampering and wrong keys", async () => {
    const { keyMaterial, kek } = await freshMaterial();
    await expect(verifyKeyMaterialMac({ ...keyMaterial, rev: 99 }, kek)).resolves.toBe(false);
    await expect(verifyKeyMaterialMac(keyMaterial, generateSymmetricKey())).resolves.toBe(false);
    await expect(
      unlockKeyMaterial({ ...keyMaterial, wrappedMasterKey: b64uEncode(new Uint8Array(60)) }, kek)
    ).rejects.toThrow();
  });

  it("adds and removes vault keys while preserving others", async () => {
    const { keyMaterial, kek, masterKey } = await freshMaterial();
    const vkA = generateSymmetricKey();
    const vkB = generateSymmetricKey();
    const withA = await withVaultKey(keyMaterial, kek, "vaultA", 1, vkA);
    const withAB = await withVaultKey(withA, kek, "vaultB", 1, vkB);
    expect(withAB.rev).toBe(keyMaterial.rev + 2);
    const a = await getVaultKey(withAB, masterKey, "vaultA");
    const b = await getVaultKey(withAB, masterKey, "vaultB");
    expect(constantTimeEqual(a!.vk, vkA)).toBe(true);
    expect(constantTimeEqual(b!.vk, vkB)).toBe(true);
    const removed = await withoutVaultKey(withAB, kek, "vaultA");
    expect(await getVaultKey(removed, masterKey, "vaultA")).toBeNull();
    expect((await getVaultKey(removed, masterKey, "vaultB"))!.version).toBe(1);
    expect(await verifyKeyMaterialMac(removed, kek)).toBe(true);
  });

  it("survives a password change by re-wrapping only", async () => {
    const { keyMaterial, kek, masterKey } = await freshMaterial();
    const vk = generateSymmetricKey();
    const withVault = await withVaultKey(keyMaterial, kek, "vaultA", 1, vk);
    const newKdf = newKdfDescriptor();
    const { kek: newKek } = await deriveAccountKeys("new password", newKdf, USERNAME);
    const rewrapped = await rewrapKeyMaterial(withVault, kek, newKek);
    expect(rewrapped.kdf).toEqual(withVault.kdf);
    await expect(unlockKeyMaterial(rewrapped, kek)).rejects.toThrow();
    const unlocked = await unlockKeyMaterial(rewrapped, newKek);
    expect(constantTimeEqual(unlocked.masterKey, masterKey)).toBe(true);
    const vault = await getVaultKey(rewrapped, unlocked.masterKey, "vaultA");
    expect(constantTimeEqual(vault!.vk, vk)).toBe(true);
  });

  it("unlocks with the recovery key and re-attaches a new password", async () => {
    const recoveryKey = generateRecoveryKey();
    const created = await createAccountKeyMaterial({
      accountId: "user-1",
      username: USERNAME,
      password: PASSWORD,
      recoveryKey,
    });
    const recovered = await unlockKeyMaterialWithRecovery(created.keyMaterial, recoveryKey);
    expect(constantTimeEqual(recovered.masterKey, created.masterKey)).toBe(true);
    const { kek: newKek } = await deriveAccountKeys("brand new password", newKdfDescriptor(), USERNAME);
    const rewrapped = await rewrapKeyMaterialFromRecovery(
      created.keyMaterial,
      recoveryKey,
      newKek,
      b64uEncode(new Uint8Array(16).fill(7))
    );
    const unlocked = await unlockKeyMaterial(rewrapped, newKek);
    expect(constantTimeEqual(unlocked.masterKey, created.masterKey)).toBe(true);
    const viaOldRecovery = await unlockKeyMaterialWithRecovery(rewrapped, recoveryKey);
    expect(constantTimeEqual(viaOldRecovery.masterKey, created.masterKey)).toBe(true);
  });

  it("has a MAC that only the KEK can produce", async () => {
    const km: AccountKeyMaterial = {
      v: CRYPTO_V2_PROTOCOL,
      accountId: "x",
      username: USERNAME,
      kdf: newKdfDescriptor(),
      recovery: null,
      wrappedMasterKey: "aa",
      wrappedMasterKeyRecovery: null,
      identity: { publicKey: "bb", sealedPrivateKey: "cc" },
      vaults: {},
      rev: 1,
      mac: "",
    };
    const kek = generateSymmetricKey();
    km.mac = await macKeyMaterial(km, kek);
    expect(await verifyKeyMaterialMac(km, kek)).toBe(true);
    expect(await verifyKeyMaterialMac(km, generateSymmetricKey())).toBe(false);
  });
});

describe("cryptoV2 integrity binding", () => {
  const vk = generateSymmetricKey();

  it("accepts matching name and content", async () => {
    const key = await deriveIntegrityKey(vk);
    const mac = await computeIntegrityMac(key, "enc-name", utf8("note content"));
    expect(await verifyIntegrityMac(key, "enc-name", utf8("note content"), mac)).toBe(true);
  });

  it("rejects swapped names or changed content", async () => {
    const key = await deriveIntegrityKey(vk);
    const mac = await computeIntegrityMac(key, "enc-name", utf8("note content"));
    expect(await verifyIntegrityMac(key, "other-name", utf8("note content"), mac)).toBe(false);
    expect(await verifyIntegrityMac(key, "enc-name", utf8("tampered content"), mac)).toBe(false);
    expect(await verifyIntegrityMac(key, "enc-name", utf8("note content"), "00".repeat(32))).toBe(false);
  });
});
