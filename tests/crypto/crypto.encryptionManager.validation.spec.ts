import "./../setup";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { ValidationError, CryptoError } from "../../src/errors";

describe("EncryptionManager - input validation vs crypto errors", () => {
  it("decryptData validates presence of IV and ciphertext", async () => {
    const enc = new EncryptionManager();
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    await expect(enc.decryptData(key, "", "ct")).rejects.toBeInstanceOf(ValidationError);
    await expect(enc.decryptData(key, "iv", "")).rejects.toBeInstanceOf(ValidationError);
  });


  it("after hardening: invalid base64 surfaces as ValidationError", async () => {
    const enc = new EncryptionManager();
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    await expect(enc.decryptData(key, "!!!", "###")).rejects.toBeInstanceOf(ValidationError);
  });
});

describe("EncryptionManager - usage & key property validation (additional)", () => {
  it("encryptData rejects a key without 'encrypt' usage", async () => {
    const enc = new EncryptionManager();
    const onlyDecrypt = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["decrypt"]
    );
    await expect(enc.encryptData(onlyDecrypt, { x: 1 })).rejects.toBeInstanceOf(ValidationError);
  });

  it("decryptData rejects a key without 'decrypt' usage", async () => {
    const enc = new EncryptionManager();
    const onlyEncrypt = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    const { iv, ciphertext } = await enc.encryptData(onlyEncrypt, { ok: true });
    await expect(enc.decryptData(onlyEncrypt, iv, ciphertext)).rejects.toBeInstanceOf(ValidationError);
  });
});