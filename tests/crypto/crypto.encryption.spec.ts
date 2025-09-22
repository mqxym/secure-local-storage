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