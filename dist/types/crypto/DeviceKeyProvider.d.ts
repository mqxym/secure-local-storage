/** Public shape for configuring where the device KEK is persisted. */
export interface IdbConfig {
    dbName: string;
    storeName: string;
    keyId: string;
}
/**
 * Persists a non-extractable AES-GCM KEK in IndexedDB (origin-bound).
 * Falls back to an in-memory key if IndexedDB is unavailable or rejects storing CryptoKey.
 *
 * Now supports per-instance configuration of the IndexedDB DB/store/key id via IdbConfig.
 * If you don't pass a config, it uses SLS_CONSTANTS.IDB defaults (fully backwards compatible).
 */
export declare class DeviceKeyProvider {
    private static memoryKeys;
    static getKey(cfgIn?: Partial<IdbConfig>): Promise<CryptoKey>;
    static rotateKey(cfgIn?: Partial<IdbConfig>): Promise<CryptoKey>;
    /**
     * Remove persisted key material for this configuration and clear the in-memory copy.
     * For backward compatibility with the original implementation, this deletes the whole DB
     * (default DB name), which is fine when you use distinct dbName per tenant/config.
     * If you prefer surgical deletes, switch to opening the DB and deleting only the record.
     */
    static deletePersistent(cfgIn?: Partial<IdbConfig>): Promise<void>;
    private static generateKek;
    private static openDB;
}
