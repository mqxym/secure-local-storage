import "./../setup";
import { deriveKekFromPassword } from "../../src/crypto/KeyDerivation";
import { CryptoError, ValidationError } from "../../src/errors";
// No types for the mock; treat as any
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as argon2 from "argon2-browser";

describe("KeyDerivation", () => {
  it("validates password and salt inputs", async () => {
    await expect(deriveKekFromPassword("", new Uint8Array(16))).rejects.toBeInstanceOf(ValidationError);
    await expect(deriveKekFromPassword("pw", new Uint8Array(4))).rejects.toBeInstanceOf(ValidationError);
    await expect(
      deriveKekFromPassword("pw", undefined as unknown as Uint8Array)
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("wraps argon2 failures as CryptoError", async () => {
    const spy = jest.spyOn(argon2, "hash").mockRejectedValueOnce(new Error("boom"));
    await expect(deriveKekFromPassword("pw", new Uint8Array(16))).rejects.toBeInstanceOf(CryptoError);
    spy.mockRestore();
  });
});

describe("KeyDerivation - extra input validation", () => {
  it("rejects non-integer or non-positive iteration counts", async () => {
    await expect(deriveKekFromPassword("pw", new Uint8Array(16), 0)).rejects.toBeInstanceOf(ValidationError);
    // 1.5 should be invalid
    await expect(deriveKekFromPassword("pw", new Uint8Array(16), 1.5)).rejects.toBeInstanceOf(ValidationError);
    await expect(deriveKekFromPassword("pw", new Uint8Array(16), -1)).rejects.toBeInstanceOf(ValidationError);
  });

  it("rejects unreasonably high iteration counts", async () => {
    await expect(deriveKekFromPassword("pw", new Uint8Array(16), 10_000)).rejects.toBeInstanceOf(ValidationError);
  });
});