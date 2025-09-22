export declare class EncryptionManager {
    generateSaltB64(): string;
    createDek(): Promise<CryptoKey>;
    encryptData(key: CryptoKey, obj: unknown): Promise<{
        iv: string;
        ciphertext: string;
    }>;
    decryptData<T = unknown>(key: CryptoKey, ivB64: string, ctB64: string): Promise<T>;
    unwrapDek(ivWrapB64: string, wrappedB64: string, kek: CryptoKey, forWrapping?: boolean): Promise<CryptoKey>;
    wrapDek(dek: CryptoKey, kek: CryptoKey): Promise<{
        ivWrap: string;
        wrappedKey: string;
    }>;
}
