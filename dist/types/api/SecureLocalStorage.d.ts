import { SecureDataView } from "../utils/secureDataView";
export interface SecureLocalStorageOptions {
    /** Override the localStorage key (for multi-tenant apps or tests). */
    storageKey?: string;
    /** Override IndexedDB configuration (for multi-tenant apps or tests). */
    idbConfig?: {
        dbName?: string;
        storeName?: string;
        keyId?: string;
    };
}
export declare class SecureLocalStorage {
    private readonly store;
    private readonly enc;
    private readonly session;
    private config;
    private dek;
    private ready;
    private readonly idbConfig;
    readonly DATA_VERSION: number;
    constructor(opts?: SecureLocalStorageOptions);
    isUsingMasterPassword(): boolean;
    /** Unlock session with master password (no-op in device mode). */
    unlock(masterPassword: string): Promise<void>;
    /** Set a master password (switch from device mode to master mode). */
    setMasterPassword(masterPassword: string): Promise<void>;
    /** Remove master password, re-wrapping DEK with device-bound KEK. Requires unlocked session. */
    removeMasterPassword(): Promise<void>;
    /** Rotate master password atomically. */
    rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void>;
    /** Lock the session (clears derived KEK & DEK from memory). */
    lock(): void;
    /** Rotate DEK and device KEK. Allowed only in password-less mode. */
    rotateKeys(): Promise<void>;
    /** Get decrypted data as a wipeable view object. */
    getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>>;
    /** Replace data with the provided plain object. */
    setData<T extends Record<string, unknown>>(value: T): Promise<void>;
    /**
     * Export the encrypted bundle as JSON string.
     * - If `customExportPassword` provided: derive export KEK (Argon2id) and rewrap DEK accordingly (mPw=false).
     * - If absent and in master mode: exports current config wrapped with master password (mPw=true).
     */
    exportData(customExportPassword?: string): Promise<string>;
    /**
     * Import previously exported JSON.
     * - If bundle.mPw===true OR header.rounds>1 and no mPw flag: expects master password.
     * - Else expects export password.
     * After import, rewrap to device mode if using export password.
     */
    importData(serialized: string, password?: string): Promise<string>;
    /** Clear all data (localStorage + IndexedDB KEK) and reinitialize fresh empty store in device mode. */
    clear(): Promise<void>;
    private initialize;
    private persist;
    private requireConfig;
    private requireUnlocked;
    private sessionKekOrThrow;
    private ensureDekLoaded;
    private unwrapDekWithKek;
}
