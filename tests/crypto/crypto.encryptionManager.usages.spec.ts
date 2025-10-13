import "../setup";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { base64ToBytes } from "../../src/utils/base64";
import { SLS_CONSTANTS } from "../../src/constants";
import { CryptoError, ValidationError } from "../../src/errors";

describe("EncryptionManager - key usage validation & primitives", () => {
  it("wrapDek fails with a KEK that lacks wrapKey usage", async () => {
    const enc = new EncryptionManager();
    const dek = await enc.createDek();
    // Wrong KEK usages
    const kekWrong = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );

    await expect(enc.wrapDek(dek, kekWrong)).rejects.toBeInstanceOf(ValidationError);
  });

  it("generateSaltB64 yields 16 bytes and is random", () => {
    const enc = new EncryptionManager();
    const s1 = enc.generateSaltB64();
    const s2 = enc.generateSaltB64();
    const b1 = base64ToBytes(s1);
    const b2 = base64ToBytes(s2);

    expect(b1.byteLength).toBe(SLS_CONSTANTS.SALT_LEN);
    expect(b2.byteLength).toBe(SLS_CONSTANTS.SALT_LEN);
    // Extremely unlikely to collide; this checks randomness works
    expect(s1 === s2).toBe(false);
  });
});