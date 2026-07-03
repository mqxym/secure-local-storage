import "./../setup";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { base64ToBytes, bytesToBase64 } from "../../src/utils/base64";
import { CryptoError } from "../../src/errors";

describe("EncryptionManager", () => {
  it("decryptData fails with wrong key and with tampered ciphertext", async () => {
    const enc = new EncryptionManager();
    const key1 = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const key2 = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

    const { iv, ciphertext } = await enc.encryptData(key1, { x: 1 });
    await expect(enc.decryptData(key2, iv, ciphertext)).rejects.toBeInstanceOf(CryptoError);

    // Tamper with ciphertext
    const ct = base64ToBytes(ciphertext);
    ct[0] = ct[0] ^ 0xff;
    const tampered = bytesToBase64(ct);
    await expect(enc.decryptData(key1, iv, tampered)).rejects.toBeInstanceOf(CryptoError);
  });

  it("unwrapDek fails with the wrong KEK", async () => {
    const enc = new EncryptionManager();
    const dek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const kek1 = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
    const kek2 = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);

    const wrapped = await enc.wrapDek(dek, kek1);
    await expect(enc.unwrapDek(wrapped.ivWrap, wrapped.wrappedKey, kek2, false)).rejects.toBeInstanceOf(CryptoError);
  });
});

describe("EncryptionManager - AAD binding & empty payloads", () => {
  it("round-trips an empty object", async () => {
    const enc = new EncryptionManager();
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const { iv, ciphertext } = await enc.encryptData(key, {});
    const out = await enc.decryptData<Record<string, unknown>>(key, iv, ciphertext);
    expect(out).toEqual({});
  });

  it("decryptData fails when the AAD does not match the one used to encrypt", async () => {
    const enc = new EncryptionManager();
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const aad = new TextEncoder().encode("context-a");
    const otherAad = new TextEncoder().encode("context-b");

    const { iv, ciphertext } = await enc.encryptData(key, { x: 1 }, aad);
    // Correct AAD succeeds
    await expect(enc.decryptData(key, iv, ciphertext, aad)).resolves.toEqual({ x: 1 });
    // Wrong AAD fails
    await expect(enc.decryptData(key, iv, ciphertext, otherAad)).rejects.toBeInstanceOf(CryptoError);
    // Missing AAD fails
    await expect(enc.decryptData(key, iv, ciphertext)).rejects.toBeInstanceOf(CryptoError);
  });

  it("unwrapDek fails when the wrap AAD does not match", async () => {
    const enc = new EncryptionManager();
    const dek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const kek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
    const aad = new TextEncoder().encode("wrap-context");

    const wrapped = await enc.wrapDek(dek, kek, aad);
    await expect(
      enc.unwrapDek(wrapped.ivWrap, wrapped.wrappedKey, kek, false, new TextEncoder().encode("other"))
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it("propagates the underlying error via CryptoError.cause on decryption failure", async () => {
    const enc = new EncryptionManager();
    const key1 = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const key2 = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const { iv, ciphertext } = await enc.encryptData(key1, { x: 1 });

    let caught: unknown;
    try {
      await enc.decryptData(key2, iv, ciphertext);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CryptoError);
    expect((caught as CryptoError).cause).toBeDefined();
  });
});