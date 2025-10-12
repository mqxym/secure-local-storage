import { SecureDataView } from "../utils/secureDataView";
import type { IdbConfig } from "../crypto/DeviceKeyProvider";
/**
 * Configuration options for initializing SecureLocalStorage.
 */
export interface SecureLocalStorageOptions {
    storageKey?: string;
    idbConfig?: Partial<IdbConfig>;
}
export declare class SecureLocalStorage {
    private readonly store;
    private readonly enc;
    private readonly session;
    private config;
    private dek;
    private ready;
    private readonly idbConfig;
    private readonly storageKeyStr;
    private lastResetReason;
    /** Kept as 2 for backward compat/tests */
    readonly DATA_VERSION: number;
    constructor(opts?: SecureLocalStorageOptions);
    isUsingMasterPassword(): boolean;
    isLocked(): boolean;
    unlock(masterPassword: string): Promise<void>;
    setMasterPassword(masterPassword: string): Promise<void>;
    removeMasterPassword(): Promise<void>;
    rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void>;
    lock(): void;
    rotateKeys(): Promise<void>;
    getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>>;
    setData<T extends Record<string, unknown>>(value: T): Promise<void>;
    exportData(customExportPassword?: string): Promise<string>;
    importData(serialized: string, password?: string): Promise<string>;
    clear(): Promise<void>;
    private initialize;
    private persist;
    private requireConfig;
    private requireUnlocked;
    private sessionKekOrThrow;
    private ensureDekLoaded;
    private unwrapDekWithKek;
    private validateBundle;
    private buildWrapAad;
    private buildDataAad;
    private wrapAadFor;
    private dataAadFor;
    private isV3;
    private isV2;
    private decryptCurrentData;
    private migrateV2ToV3;
}
