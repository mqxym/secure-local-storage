import "./../setup";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { ValidationError } from "../../src/errors";
import { bytesToBase64 } from "../../src/utils/base64";

describe("EncryptionManager hardening (IV length & base64)", () => {
  it("decryptData rejects IVs that are not 12 bytes", async () => {
    const enc = new EncryptionManager();
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const { ciphertext } = await enc.encryptData(key, { ok: true });

    const badIv = bytesToBase64(new Uint8Array(8)); // 8 != 12
    await expect(enc.decryptData(key, badIv, ciphertext)).rejects.toBeInstanceOf(ValidationError);
  });

  it("unwrapDek rejects IVs that are not 12 bytes", async () => {
    const enc = new EncryptionManager();
    const dek = await enc.createDek();
    const kek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
    const wrapped = await enc.wrapDek(dek, kek);

    const badIv = bytesToBase64(new Uint8Array(16)); // 16 != 12
    await expect(enc.unwrapDek(badIv, wrapped.wrappedKey, kek, false)).rejects.toBeInstanceOf(ValidationError);
  });

  it("unwrapDek validates base64 inputs", async () => {
    const enc = new EncryptionManager();
    const kek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
    await expect(enc.unwrapDek("!!!", "###", kek, false)).rejects.toBeInstanceOf(ValidationError);
  });
});


describe("EncryptionManager hardening (AES key length enforcement)", () => {
  it("wrapDek rejects KEK with wrong AES length (e.g., 128-bit)", async () => {
    const enc = new EncryptionManager();
    const dek = await enc.createDek();
    const kek128 = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 128 }, // wrong length, we require 256
      false,
      ["wrapKey", "unwrapKey"]
    );
    await expect(enc.wrapDek(dek, kek128)).rejects.toBeInstanceOf(ValidationError);
  });
});