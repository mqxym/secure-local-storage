import { SLS_CONSTANTS } from "../constants";
import { CryptoError, ValidationError } from "../errors";
// No module augmentation — treat as any-typed JS module
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as argon2 from "argon2-browser";

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  if (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength && u8.buffer instanceof ArrayBuffer) {
    return u8.buffer as ArrayBuffer;
  }
  return u8.slice().buffer as ArrayBuffer;
}

export async function deriveKekFromPassword(
  password: string,
  salt: Uint8Array,
  iterations = SLS_CONSTANTS.ARGON2.ITERATIONS
): Promise<CryptoKey> {
  if (typeof password !== "string" || password.length === 0) {
    throw new ValidationError("Password must be a non-empty string");
  }
  if (!(salt instanceof Uint8Array) || salt.byteLength < SLS_CONSTANTS.SALT_LEN) {
    throw new ValidationError(`Salt must be Uint8Array with length >= ${SLS_CONSTANTS.SALT_LEN}`);
  }
  const MAX_ITERATIONS = 64;
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
    throw new ValidationError(`iterations must be an integer in [1, ${MAX_ITERATIONS}]`);
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

  if (!result?.hash) throw new CryptoError("Argon2 returned no hash");

  try {
    return await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(result.hash),
      { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
      false,
      ["wrapKey", "unwrapKey"]
    );
  } catch (e) {
    throw new CryptoError(`Failed to import derived key: ${(e as Error)?.message ?? e}`);
  }
}