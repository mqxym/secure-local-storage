/**
 * Persists a non-extractable AES-GCM KEK in IndexedDB (origin-bound).
 * Falls back to an in-memory key if IndexedDB is unavailable or rejects storing CryptoKey.
 */
export declare class DeviceKeyProvider {
    private static memoryKey;
    static getKey(): Promise<CryptoKey>;
    static rotateKey(): Promise<CryptoKey>;
    static deletePersistent(): Promise<void>;
    private static generateKek;
    private static openDB;
}
