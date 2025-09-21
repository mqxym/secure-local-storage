import { SLS_CONSTANTS } from "../constants";
import { base64ToBytes, bytesToBase64 } from "../utils/base64";
import { CryptoError } from "../errors";

export class EncryptionManager {
  /** Random base64 salt */
  generateSaltB64(): string {
    const salt = new Uint8Array(SLS_CONSTANTS.SALT_LEN);
    crypto.getRandomValues(salt);
    return bytesToBase64(salt);
  }

  /** Create a new DEK (extractable so it can be wrapped; unwrapped for use with extractable=false) */
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
      const ct = await crypto.subtle.encrypt({ name: SLS_CONSTANTS.AES.NAME, iv }, key, data);
      return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(ct) };
    } catch (e) {
      throw new CryptoError(`Encryption failed: ${(e as Error)?.message ?? e}`);
    }
  }

  async decryptData<T = unknown>(key: CryptoKey, ivB64: string, ctB64: string): Promise<T> {
    try {
      const iv = base64ToBytes(ivB64);
      const ct = base64ToBytes(ctB64);
      const pt = await crypto.subtle.decrypt({ name: SLS_CONSTANTS.AES.NAME, iv }, key, ct);
      return JSON.parse(new TextDecoder().decode(pt)) as T;
    } catch (e) {
      throw new CryptoError(`Decryption failed: ${(e as Error)?.message ?? e}`);
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

  async unwrapDek(
    ivWrapB64: string,
    wrappedB64: string,
    kek: CryptoKey,
    forWrapping = false
  ): Promise<CryptoKey> {
    try {
      const iv = base64ToBytes(ivWrapB64);
      const wrapped = base64ToBytes(wrappedB64);
      return await crypto.subtle.unwrapKey(
        "raw",
        wrapped,
        kek,
        { name: SLS_CONSTANTS.AES.NAME, iv },
        { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
        forWrapping, // extractable if we need to wrap again
        forWrapping ? ["wrapKey", "unwrapKey", "encrypt", "decrypt"] : ["encrypt", "decrypt"]
      );
    } catch (e) {
      throw new CryptoError(`unwrapKey failed: ${(e as Error)?.message ?? e}`);
    }
  }
}