import { EncryptionManager } from "../crypto/EncryptionManager";
import { DeviceKeyProvider } from "../crypto/DeviceKeyProvider";
import { deriveKekFromPassword } from "../crypto/KeyDerivation";
import { SessionKeyCache } from "../crypto/SessionKeyCache";
import { StorageService } from "../storage/StorageService";
import type { PersistedConfig, PersistedConfigV2 } from "../types";
import { SecureDataView } from "../utils/secureDataView";
import type { IdbConfig } from "../crypto/DeviceKeyProvider";
import { VersionManager } from "./sls/VersionManager";
import { State } from "./states/BaseState";
export interface SecureLocalStorageOptions {
    storageKey?: string;
    idbConfig?: Partial<IdbConfig>;
}
export declare class SecureLocalStorage {
    private state;
    readonly store: StorageService;
    readonly enc: EncryptionManager;
    readonly session: SessionKeyCache;
    config: PersistedConfig | null;
    dek: CryptoKey | null;
    private ready;
    readonly idbConfig: {
        dbName: string;
        storeName: string;
        keyId: string;
    };
    readonly storageKeyStr: string;
    readonly versionManager: VersionManager;
    lastResetReason: "invalid-config" | "device-kek-mismatch" | null;
    readonly DATA_VERSION: number;
    readonly deviceKeyProvider: typeof DeviceKeyProvider;
    readonly deriveKekFromPassword: typeof deriveKekFromPassword;
    constructor(opts?: SecureLocalStorageOptions);
    transitionTo(state: State): void;
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
    persist(): void;
    requireConfig(): void;
    requireUnlocked(): void;
    sessionKekOrThrow(): CryptoKey;
    ensureDekLoaded(): Promise<void>;
    unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean, aad?: Uint8Array): Promise<void>;
    validateBundle(bundle: PersistedConfig): void;
    decryptCurrentData(): Promise<Record<string, unknown>>;
    migrateV2ToV3(mode: "device" | "master", v2: PersistedConfigV2, kek: CryptoKey): Promise<void>;
}
