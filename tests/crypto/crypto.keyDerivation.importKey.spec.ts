import "../setup";
import { deriveKekFromPassword } from "../../src/crypto/KeyDerivation";
import { CryptoError } from "../../src/errors";
import * as argon2 from "argon2-browser";

describe("deriveKekFromPassword wraps importKey failures", () => {
  it("wraps subtle.importKey errors as CryptoError", async () => {
    const argon2Spy = jest.spyOn(argon2, "hash").mockResolvedValue({ hash: new Uint8Array(32) });
    const importKeySpy = jest.spyOn(crypto.subtle, "importKey").mockRejectedValueOnce(new Error("import-failed"));
    await expect(deriveKekFromPassword("pw", new Uint8Array(16))).rejects.toBeInstanceOf(CryptoError);
    argon2Spy.mockRestore();
    importKeySpy.mockRestore();
  });
});

describe("deriveKekFromPassword - unexpected KDF output size", () => {
  it("throws CryptoError when argon2 returns a hash of unexpected length", async () => {
    const spy = jest
      .spyOn(argon2, "hash")
      // return a 16-byte hash instead of 32
      .mockResolvedValue({ hash: new Uint8Array(16) });

    await expect(deriveKekFromPassword("pw", new Uint8Array(16))).rejects.toBeInstanceOf(CryptoError);
    spy.mockRestore();
  });
});