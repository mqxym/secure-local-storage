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