import { SLS_CONSTANTS } from "../constants";
import { base64ToBytes, bytesToBase64 } from "../utils/base64";
import { CryptoError, ValidationError } from "../errors";
import { asArrayBuffer } from "../utils/typedArray";

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
    this.assertKey(key, ["encrypt"], "encryptData()");
    try {
      const iv = new Uint8Array(SLS_CONSTANTS.AES.IV_LENGTH);
      crypto.getRandomValues(iv);
      const data = new TextEncoder().encode(JSON.stringify(obj));
      const algo: AesGcmParams = aad
        ? { name: SLS_CONSTANTS.AES.NAME, iv: iv as BufferSource, additionalData: aad as BufferSource}
        : { name: SLS_CONSTANTS.AES.NAME, iv: iv as BufferSource};

      const ct = await crypto.subtle.encrypt(algo, key, asArrayBuffer(data));
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
      pt = await crypto.subtle.decrypt(algo, key, asArrayBuffer(ct));
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
    this.assertKey(kek, ["unwrapKey"], "unwrapDek()");
    try {
      const algo: AesGcmParams = aad
        ? { name: SLS_CONSTANTS.AES.NAME, iv: ivBytes as BufferSource, additionalData: aad as BufferSource }
        : { name: SLS_CONSTANTS.AES.NAME, iv: ivBytes as BufferSource };

      return await crypto.subtle.unwrapKey(
        "raw",
        asArrayBuffer(wrapped),
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
    this.assertKey(kek, ["wrapKey"], "wrapDek()");
    try {
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
    const alg = key?.algorithm as Partial<AesKeyGenParams> & { name?: string } | undefined;

    if (!key || alg?.name !== SLS_CONSTANTS.AES.NAME) {
      throw new ValidationError(`Invalid key algorithm for ${where}; expected ${SLS_CONSTANTS.AES.NAME}`);
    }

    // Enforce key size when available from the WebCrypto implementation
    const len = typeof alg?.length === "number" ? alg!.length : undefined;
    if (len !== undefined && len !== SLS_CONSTANTS.AES.LENGTH) {
      throw new ValidationError(`Invalid key length for ${where}; expected ${SLS_CONSTANTS.AES.LENGTH} bits`);
    }

    for (const u of required) {
      if (!key.usages.includes(u)) {
        throw new ValidationError(`Key missing "${u}" usage for ${where}`);
      }
  }
  } 
}