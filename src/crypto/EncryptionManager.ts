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

  async encryptData(
    key: CryptoKey,
    obj: unknown,
    aad?: Uint8Array
  ): Promise<{ iv: string; ciphertext: string }> {
    try {
      this.assertKey(key, ["encrypt"], "encryptData()");
      const iv = new Uint8Array(SLS_CONSTANTS.AES.IV_LENGTH);
      crypto.getRandomValues(iv);
      const data = new TextEncoder().encode(JSON.stringify(obj));
      const algo: AesGcmParams = aad
        ? { name: SLS_CONSTANTS.AES.NAME, iv: iv as BufferSource, additionalData: aad as BufferSource}
        : { name: SLS_CONSTANTS.AES.NAME, iv: iv as BufferSource};

      const ct = await crypto.subtle.encrypt(algo, key, toArrayBuffer(data));
      return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(ct) };
    } catch (e) {
      throw new CryptoError(`Encryption failed: ${(e as Error)?.message ?? e}`);
    }
  }

  async decryptData<T = unknown>(
    key: CryptoKey,
    ivB64: string,
    ctB64: string,
    aad?: Uint8Array
  ): Promise<T> {
    if (!ivB64 || !ctB64) throw new ValidationError("IV and ciphertext are required");

    const ivBytes = base64ToBytes(ivB64) as BufferSource;
    const ct = base64ToBytes(ctB64);

    if (ivBytes.byteLength !== SLS_CONSTANTS.AES.IV_LENGTH) {
      throw new ValidationError(`IV must be ${SLS_CONSTANTS.AES.IV_LENGTH} bytes`);
    }

    this.assertKey(key, ["decrypt"], "decryptData()");

    let pt: ArrayBuffer;
    try {
      const algo: AesGcmParams = aad
        ? { name: SLS_CONSTANTS.AES.NAME, iv: ivBytes as BufferSource, additionalData: aad as BufferSource }
        : { name: SLS_CONSTANTS.AES.NAME, iv: ivBytes as BufferSource };
      pt = await crypto.subtle.decrypt(algo, key, toArrayBuffer(ct));
    } catch (e) {
      throw new CryptoError(`Invalid key or data.`);
    }

    try {
      return JSON.parse(new TextDecoder().decode(pt)) as T;
    } catch {
      throw new ValidationError("Decrypted data is not valid JSON");
    }
  }

  async unwrapDek(
    ivWrapB64: string,
    wrappedB64: string,
    kek: CryptoKey,
    forWrapping = false,
    aad?: Uint8Array
  ): Promise<CryptoKey> {
    const ivBytes = base64ToBytes(ivWrapB64) as BufferSource; // may throw ValidationError
    const wrapped = base64ToBytes(wrappedB64);

    if (ivBytes.byteLength !== SLS_CONSTANTS.AES.IV_LENGTH) {
      throw new ValidationError(`Wrap IV must be ${SLS_CONSTANTS.AES.IV_LENGTH} bytes`);
    }

    try {
      this.assertKey(kek, ["unwrapKey"], "unwrapDek()");
      const algo: AesGcmParams = aad
        ? { name: SLS_CONSTANTS.AES.NAME, iv: ivBytes as BufferSource, additionalData: aad as BufferSource }
        : { name: SLS_CONSTANTS.AES.NAME, iv: ivBytes as BufferSource };

      return await crypto.subtle.unwrapKey(
        "raw",
        toArrayBuffer(wrapped),
        kek,
        algo,
        { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
        forWrapping,
        forWrapping ? ["wrapKey", "unwrapKey", "encrypt", "decrypt"] : ["encrypt", "decrypt"]
      );
    } catch {
      throw new CryptoError("Invalid key or data.");
    }
  }

  async wrapDek(
    dek: CryptoKey,
    kek: CryptoKey,
    aad?: Uint8Array
  ): Promise<{ ivWrap: string; wrappedKey: string }> {
    try {
      this.assertKey(kek, ["wrapKey"], "wrapDek()");
      const iv = new Uint8Array(SLS_CONSTANTS.AES.IV_LENGTH);
      crypto.getRandomValues(iv);
      const algo: AesGcmParams = aad
        ? { name: SLS_CONSTANTS.AES.NAME, iv: iv as BufferSource, additionalData: aad  as BufferSource}
        : { name: SLS_CONSTANTS.AES.NAME, iv:iv as BufferSource };
      const wrapped = await crypto.subtle.wrapKey("raw", dek, kek, algo);
      return { ivWrap: bytesToBase64(iv), wrappedKey: bytesToBase64(wrapped) };
    } catch (e) {
      throw new CryptoError(`wrapKey failed: ${(e as Error)?.message ?? e}`);
    }
  }

  private assertKey(key: CryptoKey, required: KeyUsage[], where: string): void {
    if (!key || (key.algorithm as { name?: string })?.name !== SLS_CONSTANTS.AES.NAME) {
      throw new ValidationError(`Invalid key algorithm for ${where}; expected ${SLS_CONSTANTS.AES.NAME}`);
    }
    for (const u of required) {
      if (!key.usages.includes(u)) {
        throw new ValidationError(`Key missing "${u}" usage for ${where}`);
      }
    }
  } 
}