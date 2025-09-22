import { SLS_CONSTANTS } from "../constants";
import { base64ToBytes, bytesToBase64 } from "../utils/base64";
import { CryptoError, ValidationError } from "../errors";

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  if (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength && u8.buffer instanceof ArrayBuffer) {
    return u8.buffer as ArrayBuffer;
  }
  return u8.slice().buffer as ArrayBuffer;
}

export class EncryptionManager {
  generateSaltB64(): string {
    const salt = new Uint8Array(SLS_CONSTANTS.SALT_LEN);
    crypto.getRandomValues(salt);
    return bytesToBase64(salt);
  }

  async createDek(): Promise<CryptoKey> {
    try {
      return await crypto.subtle.generateKey(
        { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
        true,
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
      );
    } catch (e) {
      throw new CryptoError(`Failed to generate DEK: ${(e as Error)?.message ?? e}`);
    }
  }

  async encryptData(key: CryptoKey, obj: unknown): Promise<{ iv: string; ciphertext: string }> {
    try {
      const iv = new Uint8Array(SLS_CONSTANTS.AES.IV_LENGTH);
      crypto.getRandomValues(iv);
      const data = new TextEncoder().encode(JSON.stringify(obj));
      const ct = await crypto.subtle.encrypt({ name: SLS_CONSTANTS.AES.NAME, iv }, key, toArrayBuffer(data));
      return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(ct) };
    } catch (e) {
      throw new CryptoError(`Encryption failed: ${(e as Error)?.message ?? e}`);
    }
  }

  async decryptData<T = unknown>(key: CryptoKey, ivB64: string, ctB64: string): Promise<T> {
    if (!ivB64 || !ctB64) throw new ValidationError("IV and ciphertext are required");

    let iv: BufferSource;
    let ct: Uint8Array;
    try {
      iv = base64ToBytes(ivB64) as BufferSource;
      ct = base64ToBytes(ctB64);
    } catch (e) {
      throw e;
    }

    let pt: ArrayBuffer;
    try {
      pt = await crypto.subtle.decrypt({ name: SLS_CONSTANTS.AES.NAME, iv }, key, toArrayBuffer(ct));
    } catch (e) {
      throw new CryptoError(`Decryption failed: Invalid Data?`);
    }

    try {
      return JSON.parse(new TextDecoder().decode(pt)) as T;
    } catch {
      throw new ValidationError("Decrypted data is not valid JSON");
    }
  }

  async unwrapDek(ivWrapB64: string, wrappedB64: string, kek: CryptoKey, forWrapping = false): Promise<CryptoKey> {
    let iv: BufferSource;
    let wrapped: Uint8Array;
    try {
      iv = base64ToBytes(ivWrapB64) as BufferSource; // may throw ValidationError
      wrapped = base64ToBytes(wrappedB64);
    } catch (e) {
      throw e; // propagate ValidationError
    }

    try {
      return await crypto.subtle.unwrapKey(
        "raw",
        toArrayBuffer(wrapped),
        kek,
        { name: SLS_CONSTANTS.AES.NAME, iv },
        { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
        forWrapping,
        forWrapping ? ["wrapKey", "unwrapKey", "encrypt", "decrypt"] : ["encrypt", "decrypt"]
      );
    } catch (e) {
      throw new CryptoError("Key unwrapping failed. Invalid data?");
    }
  }

  async wrapDek(dek: CryptoKey, kek: CryptoKey): Promise<{ ivWrap: string; wrappedKey: string }> {
    try {
      const iv = new Uint8Array(SLS_CONSTANTS.AES.IV_LENGTH);
      crypto.getRandomValues(iv);
      const wrapped = await crypto.subtle.wrapKey("raw", dek, kek, { name: SLS_CONSTANTS.AES.NAME, iv });
      return { ivWrap: bytesToBase64(iv), wrappedKey: bytesToBase64(wrapped) };
    } catch (e) {
      throw new CryptoError(`wrapKey failed: ${(e as Error)?.message ?? e}`);
    }
  }
}