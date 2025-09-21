import { SLS_CONSTANTS } from "../constants";
import { CryptoError, ValidationError } from "../errors";

// Minimal type declarations for argon2-browser
// (kept inline to avoid external @types)
declare module "argon2-browser" {
  export const ArgonType: { Argon2id: number };
  export function hash(opts: {
    pass: string | Uint8Array;
    salt: Uint8Array;
    time: number;       // iterations
    mem: number;        // KiB
    hashLen: number;    // bytes
    parallelism: number;
    type: number;       // ArgonType.Argon2id
  }): Promise<{ hash: Uint8Array }>;
}
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as argon2 from "argon2-browser";

/** Derive a non-extractable KEK (CryptoKey) from password using Argon2id. */
export async function deriveKekFromPassword(
  password: string,
  salt: Uint8Array,
  iterations = SLS_CONSTANTS.ARGON2.ITERATIONS
): Promise<CryptoKey> {
  if (typeof password !== "string" || password.length === 0) {
    throw new ValidationError("Password must be a non-empty string");
  }
  if (!(salt instanceof Uint8Array) || salt.byteLength < 8) {
    throw new ValidationError("Salt must be Uint8Array with length >= 8");
  }

  let result: { hash: Uint8Array };
  try {
    result = await argon2.hash({
      pass: password,
      salt,
      time: iterations,
      mem: SLS_CONSTANTS.ARGON2.MEMORY_KIB,
      hashLen: SLS_CONSTANTS.ARGON2.HASH_LEN,
      parallelism: SLS_CONSTANTS.ARGON2.PARALLELISM,
      type: argon2.ArgonType.Argon2id
    });
  } catch (e) {
    throw new CryptoError(`Argon2 derivation failed: ${(e as Error)?.message ?? e}`);
  }

  if (!result?.hash) {
    throw new CryptoError("Argon2 returned no hash");
  }

  try {
    return await crypto.subtle.importKey(
      "raw",
      result.hash,
      { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
      false,
      ["wrapKey", "unwrapKey"]
    );
  } catch (e) {
    throw new CryptoError(`Failed to import derived key: ${(e as Error)?.message ?? e}`);
  }
}