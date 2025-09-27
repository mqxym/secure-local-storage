import "../setup";
import { deriveKekFromPassword } from "../../src/crypto/KeyDerivation";
import { CryptoError } from "../../src/errors";

describe("deriveKekFromPassword wraps importKey failures", () => {
  it("wraps subtle.importKey errors as CryptoError", async () => {
    const spy = jest.spyOn(crypto.subtle, "importKey").mockRejectedValueOnce(new Error("import-failed"));
    await expect(deriveKekFromPassword("pw", new Uint8Array(16))).rejects.toBeInstanceOf(CryptoError);
    spy.mockRestore();
  });
});