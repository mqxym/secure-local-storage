import { expect, test, describe, spyOn } from "bun:test";
import { deriveKekFromPassword } from "../../src/crypto/KeyDerivation";
import { CryptoError } from "../../src/errors";

describe("deriveKekFromPassword wraps importKey failures", () => {
  test("wraps subtle.importKey errors as CryptoError", async () => {
    const originalImportKey = crypto.subtle.importKey;
    // @ts-ignore
    crypto.subtle.importKey = async () => {
      throw new Error("import-failed");
    };

    await expect(deriveKekFromPassword("pw", new Uint8Array(16))).rejects.toBeInstanceOf(CryptoError);

    // @ts-ignore
    crypto.subtle.importKey = originalImportKey;
  });
});