export declare class EncryptionManager {
    generateSaltB64(): string;
    createDek(): Promise<CryptoKey>;
    encryptData(key: CryptoKey, obj: unknown, aad?: Uint8Array): Promise<{
        iv: string;
        ciphertext: string;
    }>;
    decryptData<T = unknown>(key: CryptoKey, ivB64: string, ctB64: string, aad?: Uint8Array): Promise<T>;
    unwrapDek(ivWrapB64: string, wrappedB64: string, kek: CryptoKey, forWrapping?: boolean, aad?: Uint8Array): Promise<CryptoKey>;
    wrapDek(dek: CryptoKey, kek: CryptoKey, aad?: Uint8Array): Promise<{
        ivWrap: string;
        wrappedKey: string;
    }>;
    private assertKey;
}
